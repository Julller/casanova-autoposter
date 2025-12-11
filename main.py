"""
CasaNova AutoPoster - Backend API
Autopublicador de contenido para redes sociales
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps
import requests
import os
import jwt
import hashlib
import hmac
import base64
import urllib.parse
import time
import uuid
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
CORS(app)

# Configuración
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'casanova-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///autoposter.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Facebook App Config
FB_APP_ID = os.getenv('FB_APP_ID', '1127681912914109')
FB_APP_SECRET = os.getenv('FB_APP_SECRET', '')
FB_REDIRECT_URI = os.getenv('FB_REDIRECT_URI', 'https://social.casanovastore.shop/callback.html')

db = SQLAlchemy(app)
scheduler = BackgroundScheduler()

# ==================== MODELOS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accounts = db.relationship('SocialAccount', backref='user', lazy=True)
    posts = db.relationship('Post', backref='user', lazy=True)

class SocialAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    platform = db.Column(db.String(50), nullable=False)
    account_id = db.Column(db.String(100), nullable=False)
    account_name = db.Column(db.String(200))
    access_token = db.Column(db.Text, nullable=False)
    token_expires = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500))
    link_url = db.Column(db.String(500))
    scheduled_time = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='draft')
    platforms = db.Column(db.String(200))
    published_ids = db.Column(db.Text)
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    published_at = db.Column(db.DateTime)

class Template(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    platforms = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== AUTENTICACIÓN ====================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token requerido'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'Usuario no encontrado'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# ==================== RUTAS DE AUTENTICACIÓN ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email ya registrado'}), 400
    
    user = User(
        email=data['email'],
        password_hash=hash_password(data['password'])
    )
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'message': 'Usuario creado',
        'token': create_token(user.id),
        'user': {'id': user.id, 'email': user.email}
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or user.password_hash != hash_password(data['password']):
        return jsonify({'error': 'Credenciales inválidas'}), 401
    
    return jsonify({
        'token': create_token(user.id),
        'user': {'id': user.id, 'email': user.email}
    })

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_me(current_user):
    return jsonify({
        'id': current_user.id,
        'email': current_user.email
    })

# ==================== FACEBOOK/INSTAGRAM AUTH ====================

@app.route('/api/social/facebook/auth-url', methods=['GET'])
@token_required
def get_facebook_auth_url(current_user):
    scopes = 'pages_manage_posts,pages_read_engagement'
    url = f"https://www.facebook.com/v18.0/dialog/oauth?client_id={FB_APP_ID}&redirect_uri={FB_REDIRECT_URI}&scope={scopes}&state={current_user.id}"
    return jsonify({'url': url})

@app.route('/api/social/facebook/callback', methods=['POST'])
@token_required
def facebook_callback(current_user):
    code = request.json.get('code')
    
    print(f"=== Facebook Callback ===")
    print(f"Code received: {code[:50]}..." if code else "No code")
    print(f"FB_APP_ID: {FB_APP_ID}")
    print(f"FB_REDIRECT_URI: {FB_REDIRECT_URI}")
    
    token_url = f"https://graph.facebook.com/v18.0/oauth/access_token"
    params = {
        'client_id': FB_APP_ID,
        'client_secret': FB_APP_SECRET,
        'redirect_uri': FB_REDIRECT_URI,
        'code': code
    }
    
    response = requests.get(token_url, params=params)
    print(f"Token response status: {response.status_code}")
    print(f"Token response: {response.text}")
    
    if response.status_code != 200:
        return jsonify({'error': 'Error al obtener token', 'details': response.text}), 400
    
    token_data = response.json()
    access_token = token_data['access_token']
    
    long_token_url = f"https://graph.facebook.com/v18.0/oauth/access_token"
    long_params = {
        'grant_type': 'fb_exchange_token',
        'client_id': FB_APP_ID,
        'client_secret': FB_APP_SECRET,
        'fb_exchange_token': access_token
    }
    
    long_response = requests.get(long_token_url, params=long_params)
    if long_response.status_code == 200:
        long_data = long_response.json()
        access_token = long_data.get('access_token', access_token)
    
    pages_url = f"https://graph.facebook.com/v18.0/me/accounts?access_token={access_token}"
    pages_response = requests.get(pages_url)
    
    print(f"Pages response status: {pages_response.status_code}")
    print(f"Pages response: {pages_response.text}")
    
    if pages_response.status_code != 200:
        return jsonify({'error': 'Error al obtener páginas', 'details': pages_response.text}), 400
    
    pages = pages_response.json().get('data', [])
    added_accounts = []
    
    print(f"Found {len(pages)} pages")
    
    for page in pages:
        existing = SocialAccount.query.filter_by(
            user_id=current_user.id,
            platform='facebook',
            account_id=page['id']
        ).first()
        
        if existing:
            existing.access_token = page['access_token']
            existing.account_name = page['name']
        else:
            account = SocialAccount(
                user_id=current_user.id,
                platform='facebook',
                account_id=page['id'],
                account_name=page['name'],
                access_token=page['access_token']
            )
            db.session.add(account)
        
        added_accounts.append({'platform': 'facebook', 'name': page['name']})
        
        ig_url = f"https://graph.facebook.com/v18.0/{page['id']}?fields=instagram_business_account&access_token={page['access_token']}"
        ig_response = requests.get(ig_url)
        
        if ig_response.status_code == 200:
            ig_data = ig_response.json()
            if 'instagram_business_account' in ig_data:
                ig_id = ig_data['instagram_business_account']['id']
                
                ig_info_url = f"https://graph.facebook.com/v18.0/{ig_id}?fields=username&access_token={page['access_token']}"
                ig_info = requests.get(ig_info_url).json()
                ig_name = ig_info.get('username', 'Instagram')
                
                existing_ig = SocialAccount.query.filter_by(
                    user_id=current_user.id,
                    platform='instagram',
                    account_id=ig_id
                ).first()
                
                if existing_ig:
                    existing_ig.access_token = page['access_token']
                    existing_ig.account_name = ig_name
                else:
                    ig_account = SocialAccount(
                        user_id=current_user.id,
                        platform='instagram',
                        account_id=ig_id,
                        account_name=ig_name,
                        access_token=page['access_token']
                    )
                    db.session.add(ig_account)
                
                added_accounts.append({'platform': 'instagram', 'name': ig_name})
    
    db.session.commit()
    print(f"Added accounts: {added_accounts}")
    return jsonify({'accounts': added_accounts})

# ==================== AGREGAR CUENTA MANUAL ====================

@app.route('/api/social/accounts/add', methods=['POST'])
@token_required
def add_account_manual(current_user):
    """Agregar cuenta manualmente con token"""
    import json as json_lib
    
    data = request.json
    
    platform = data.get('platform', 'facebook')
    account_id = data.get('account_id')
    account_name = data.get('account_name')
    access_token = data.get('access_token')
    
    # Para Twitter, guardar todas las credenciales como JSON
    if platform == 'twitter':
        twitter_creds = {
            'api_key': data.get('api_key'),
            'api_secret': data.get('api_secret'),
            'access_token': data.get('access_token'),
            'access_token_secret': data.get('access_token_secret')
        }
        access_token = json_lib.dumps(twitter_creds)
    
    if not account_id:
        return jsonify({'error': 'account_id es requerido'}), 400
    
    # Verificar si ya existe
    existing = SocialAccount.query.filter_by(
        user_id=current_user.id,
        platform=platform,
        account_id=account_id
    ).first()
    
    if existing:
        existing.access_token = access_token
        existing.account_name = account_name
        existing.is_active = True
        db.session.commit()
        return jsonify({'message': 'Cuenta actualizada', 'id': existing.id})
    
    # Crear nueva cuenta
    account = SocialAccount(
        user_id=current_user.id,
        platform=platform,
        account_id=account_id,
        account_name=account_name,
        access_token=access_token
    )
    db.session.add(account)
    db.session.commit()
    
    return jsonify({'message': 'Cuenta agregada', 'id': account.id})

@app.route('/api/social/accounts', methods=['GET'])
@token_required
def get_accounts(current_user):
    accounts = SocialAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    return jsonify([{
        'id': a.id,
        'platform': a.platform,
        'account_id': a.account_id,
        'account_name': a.account_name
    } for a in accounts])

@app.route('/api/social/accounts/<int:account_id>', methods=['DELETE'])
@token_required
def delete_account(current_user, account_id):
    account = SocialAccount.query.filter_by(id=account_id, user_id=current_user.id).first()
    if not account:
        return jsonify({'error': 'Cuenta no encontrada'}), 404
    
    account.is_active = False
    db.session.commit()
    return jsonify({'message': 'Cuenta desconectada'})

# ==================== PUBLICACIONES ====================

@app.route('/api/posts', methods=['GET'])
@token_required
def get_posts(current_user):
    status = request.args.get('status')
    query = Post.query.filter_by(user_id=current_user.id)
    
    if status:
        query = query.filter_by(status=status)
    
    posts = query.order_by(Post.created_at.desc()).limit(50).all()
    
    return jsonify([{
        'id': p.id,
        'content': p.content,
        'image_url': p.image_url,
        'link_url': p.link_url,
        'scheduled_time': p.scheduled_time.isoformat() if p.scheduled_time else None,
        'status': p.status,
        'platforms': p.platforms,
        'error_message': p.error_message,
        'created_at': p.created_at.isoformat(),
        'published_at': p.published_at.isoformat() if p.published_at else None
    } for p in posts])

@app.route('/api/posts', methods=['POST'])
@token_required
def create_post(current_user):
    data = request.json
    
    post = Post(
        user_id=current_user.id,
        content=data['content'],
        image_url=data.get('image_url'),
        link_url=data.get('link_url'),
        platforms=str(data.get('platforms', ['facebook'])),
        status='draft'
    )
    
    if data.get('scheduled_time'):
        post.scheduled_time = datetime.fromisoformat(data['scheduled_time'].replace('Z', '+00:00'))
        post.status = 'scheduled'
    
    db.session.add(post)
    db.session.commit()
    
    return jsonify({
        'id': post.id,
        'status': post.status,
        'message': 'Post creado'
    })

@app.route('/api/posts/<int:post_id>', methods=['PUT'])
@token_required
def update_post(current_user, post_id):
    post = Post.query.filter_by(id=post_id, user_id=current_user.id).first()
    if not post:
        return jsonify({'error': 'Post no encontrado'}), 404
    
    if post.status == 'published':
        return jsonify({'error': 'No se puede editar un post publicado'}), 400
    
    data = request.json
    post.content = data.get('content', post.content)
    post.image_url = data.get('image_url', post.image_url)
    post.link_url = data.get('link_url', post.link_url)
    post.platforms = str(data.get('platforms', post.platforms))
    
    if data.get('scheduled_time'):
        post.scheduled_time = datetime.fromisoformat(data['scheduled_time'].replace('Z', '+00:00'))
        post.status = 'scheduled'
    
    db.session.commit()
    return jsonify({'message': 'Post actualizado'})

@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
@token_required
def delete_post(current_user, post_id):
    post = Post.query.filter_by(id=post_id, user_id=current_user.id).first()
    if not post:
        return jsonify({'error': 'Post no encontrado'}), 404
    
    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Post eliminado'})

@app.route('/api/posts/<int:post_id>/publish', methods=['POST'])
@token_required
def publish_post(current_user, post_id):
    post = Post.query.filter_by(id=post_id, user_id=current_user.id).first()
    if not post:
        return jsonify({'error': 'Post no encontrado'}), 404
    
    result = publish_to_social(post, current_user.id)
    return jsonify(result)

def publish_to_social(post, user_id):
    import json
    platforms = eval(post.platforms) if isinstance(post.platforms, str) else post.platforms
    published_ids = {}
    errors = []
    
    print(f"=== INICIANDO PUBLICACIÓN ===")
    print(f"Post ID: {post.id}")
    print(f"Contenido: {post.content[:100]}...")
    print(f"Plataformas: {platforms}")
    print(f"User ID: {user_id}")
    
    for platform in platforms:
        print(f"\n--- Procesando {platform} ---")
        
        # Para threads, usar la misma cuenta que instagram
        query_platform = 'instagram' if platform == 'threads' else platform
        
        account = SocialAccount.query.filter_by(
            user_id=user_id,
            platform=query_platform,
            is_active=True
        ).first()
        
        if not account:
            error_msg = f"No hay cuenta de {platform} conectada"
            errors.append(error_msg)
            print(f"ERROR: {error_msg}")
            continue
        
        print(f"Cuenta encontrada: {account.account_name} ({account.account_id})")
        
        try:
            result = None
            if platform == 'facebook':
                result = publish_to_facebook(account, post)
            elif platform == 'instagram' or platform == 'threads':
                result = publish_to_instagram(account, post)
            elif platform == 'twitter':
                result = publish_to_twitter(account, post)
            else:
                error_msg = f"Plataforma no soportada: {platform}"
                errors.append(error_msg)
                print(f"ERROR: {error_msg}")
                continue
            
            print(f"Resultado de {platform}: {result}")
            
            if result and isinstance(result, dict):
                if 'id' in result:
                    published_ids[platform] = result['id']
                    print(f"✓ Publicado exitosamente en {platform}")
                elif 'error' in result:
                    error_msg = f"{platform}: {result['error'].get('message', str(result['error']))}"
                    errors.append(error_msg)
                    print(f"✗ Error en {platform}: {error_msg}")
                else:
                    error_msg = f"{platform}: Respuesta inesperada: {result}"
                    errors.append(error_msg)
                    print(f"✗ Respuesta inesperada en {platform}")
            else:
                error_msg = f"{platform}: Resultado inválido: {result}"
                errors.append(error_msg)
                print(f"✗ Resultado inválido en {platform}")
                
        except Exception as e:
            error_msg = f"{platform}: Exception - {str(e)}"
            errors.append(error_msg)
            print(f"✗ Exception en {platform}: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
    
    # Actualizar estado del post
    print(f"\n=== RESULTADOS FINALES ===")
    print(f"Publicados: {published_ids}")
    print(f"Errores: {errors}")
    
    if published_ids:
        post.status = 'published'
        post.published_ids = json.dumps(published_ids)
        post.published_at = datetime.utcnow()
        print("✓ Post marcado como publicado")
    else:
        post.status = 'failed'
        print("✗ Post marcado como fallido")
    
    if errors:
        post.error_message = '; '.join(errors)
        print(f"Errores guardados: {post.error_message}")
    
    try:
        db.session.commit()
        print("✓ Cambios guardados en base de datos")
    except Exception as e:
        print(f"✗ Error guardando en DB: {e}")
    
    final_result = {
        'success': len(published_ids) > 0,
        'published': published_ids,
        'errors': errors
    }
    
    print(f"Resultado final: {final_result}")
    print("=== FIN PUBLICACIÓN ===\n")
    
    return final_result

def publish_to_facebook(account, post):
    try:
        url = f"https://graph.facebook.com/v18.0/{account.account_id}/feed"
        
        data = {
            'message': post.content,
            'access_token': account.access_token
        }
        
        # Si hay imagen, publicar como foto
        if post.image_url:
            url = f"https://graph.facebook.com/v18.0/{account.account_id}/photos"
            data['url'] = post.image_url
            # Si también hay link, agregarlo al caption
            if post.link_url:
                data['caption'] = f"{post.content}\n\n🔗 {post.link_url}"
            else:
                data['caption'] = post.content
            if 'message' in data:
                del data['message']
        elif post.link_url:
            # Solo link sin imagen personalizada
            data['link'] = post.link_url
        
        print(f"Facebook request: {url}")
        print(f"Facebook data: {data}")
        
        response = requests.post(url, data=data, timeout=30)
        result = response.json()
        
        print(f"Facebook response: {response.status_code} - {result}")
        
        if response.status_code == 200 and 'id' in result:
            return {'id': result['id']}
        else:
            return {'error': {'message': str(result)}}
            
    except Exception as e:
        print(f"Facebook exception: {str(e)}")
        return {'error': {'message': str(e)}}

def publish_to_instagram(account, post):
    try:
        if not post.image_url:
            return {'error': {'message': 'Instagram requiere una imagen'}}
        
        # Paso 1: Crear contenedor de medios
        container_url = f"https://graph.facebook.com/v18.0/{account.account_id}/media"
        container_data = {
            'image_url': post.image_url,
            'caption': post.content,
            'access_token': account.access_token
        }
        
        print(f"Instagram container request: {container_url}")
        print(f"Instagram container data: {container_data}")
        
        container_response = requests.post(container_url, data=container_data, timeout=30)
        container_result = container_response.json()
        
        print(f"Instagram container response: {container_response.status_code} - {container_result}")
        
        if 'id' not in container_result:
            return {'error': {'message': f'Error creando contenedor: {str(container_result)}'}}
        
        # Paso 2: Publicar el contenedor
        publish_url = f"https://graph.facebook.com/v18.0/{account.account_id}/media_publish"
        publish_data = {
            'creation_id': container_result['id'],
            'access_token': account.access_token
        }
        
        print(f"Instagram publish request: {publish_url}")
        print(f"Instagram publish data: {publish_data}")
        
        publish_response = requests.post(publish_url, data=publish_data, timeout=30)
        publish_result = publish_response.json()
        
        print(f"Instagram publish response: {publish_response.status_code} - {publish_result}")
        
        if publish_response.status_code == 200 and 'id' in publish_result:
            return {'id': publish_result['id']}
        else:
            return {'error': {'message': f'Error publicando: {str(publish_result)}'}}
            
    except Exception as e:
        print(f"Instagram exception: {str(e)}")
        return {'error': {'message': str(e)}}

def publish_to_twitter(account, post):
    """Publicar en Twitter/X usando OAuth 1.0a"""
    import json as json_lib
    
    # Obtener credenciales almacenadas
    try:
        # Las credenciales se guardan en access_token como JSON
        creds = json_lib.loads(account.access_token)
        api_key = creds.get('api_key')
        api_secret = creds.get('api_secret')
        access_token = creds.get('access_token')
        access_token_secret = creds.get('access_token_secret')
    except:
        return {'error': {'message': 'Credenciales de Twitter inválidas'}}
    
    if not all([api_key, api_secret, access_token, access_token_secret]):
        return {'error': {'message': 'Faltan credenciales de Twitter'}}
    
    # Preparar el tweet
    tweet_text = post.content
    if post.link_url:
        tweet_text = f"{post.content}\n\n{post.link_url}"
    
    # Limitar a 280 caracteres
    if len(tweet_text) > 280:
        tweet_text = tweet_text[:277] + "..."
    
    # URL de la API de Twitter v2
    url = "https://api.twitter.com/2/tweets"
    
    # Crear firma OAuth 1.0a
    oauth_params = {
        'oauth_consumer_key': api_key,
        'oauth_token': access_token,
        'oauth_signature_method': 'HMAC-SHA1',
        'oauth_timestamp': str(int(time.time())),
        'oauth_nonce': str(uuid.uuid4().hex),
        'oauth_version': '1.0'
    }
    
    # Crear la firma
    param_string = '&'.join([f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted(oauth_params.items())])
    base_string = f"POST&{urllib.parse.quote(url, safe='')}&{urllib.parse.quote(param_string, safe='')}"
    signing_key = f"{urllib.parse.quote(api_secret, safe='')}&{urllib.parse.quote(access_token_secret, safe='')}"
    
    signature = base64.b64encode(
        hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()
    ).decode()
    
    oauth_params['oauth_signature'] = signature
    
    # Crear header de autorización
    auth_header = 'OAuth ' + ', '.join([f'{k}="{urllib.parse.quote(str(v), safe="")}"' for k, v in sorted(oauth_params.items())])
    
    headers = {
        'Authorization': auth_header,
        'Content-Type': 'application/json'
    }
    
    payload = {'text': tweet_text}
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        result = response.json()
        
        if 'data' in result and 'id' in result['data']:
            return {'id': result['data']['id']}
        else:
            error_msg = result.get('detail') or result.get('title') or str(result)
            return {'error': {'message': error_msg}}
    except Exception as e:
        return {'error': {'message': str(e)}}

# ==================== PLANTILLAS ====================

@app.route('/api/templates', methods=['GET'])
@token_required
def get_templates(current_user):
    templates = Template.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': t.id,
        'name': t.name,
        'content': t.content,
        'platforms': t.platforms
    } for t in templates])

@app.route('/api/templates', methods=['POST'])
@token_required
def create_template(current_user):
    data = request.json
    template = Template(
        user_id=current_user.id,
        name=data['name'],
        content=data['content'],
        platforms=str(data.get('platforms', []))
    )
    db.session.add(template)
    db.session.commit()
    return jsonify({'id': template.id, 'message': 'Plantilla creada'})

@app.route('/api/templates/<int:template_id>', methods=['DELETE'])
@token_required
def delete_template(current_user, template_id):
    template = Template.query.filter_by(id=template_id, user_id=current_user.id).first()
    if not template:
        return jsonify({'error': 'Plantilla no encontrada'}), 404
    
    db.session.delete(template)
    db.session.commit()
    return jsonify({'message': 'Plantilla eliminada'})

# ==================== WORDPRESS INTEGRATION ====================

@app.route('/api/wordpress/import', methods=['POST'])
@token_required
def import_from_wordpress(current_user):
    data = request.json
    wp_url = data['url'].rstrip('/')
    
    api_url = f"{wp_url}/wp-json/wp/v2/posts?per_page=10&_embed"
    
    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code != 200:
            return jsonify({'error': 'No se pudo conectar a WordPress'}), 400
        
        wp_posts = response.json()
        imported = []
        
        for wp_post in wp_posts:
            title = wp_post['title']['rendered']
            excerpt = wp_post['excerpt']['rendered'].replace('<p>', '').replace('</p>', '').strip()
            link = wp_post['link']
            
            image_url = None
            if '_embedded' in wp_post and 'wp:featuredmedia' in wp_post['_embedded']:
                media = wp_post['_embedded']['wp:featuredmedia']
                if media and len(media) > 0:
                    image_url = media[0].get('source_url')
            
            content = f"📰 {title}\n\n{excerpt}\n\n🔗 Lee más: {link}"
            
            imported.append({
                'title': title,
                'content': content,
                'image_url': image_url,
                'link_url': link
            })
        
        return jsonify({'posts': imported})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ESTADÍSTICAS ====================

@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    total_posts = Post.query.filter_by(user_id=current_user.id).count()
    published = Post.query.filter_by(user_id=current_user.id, status='published').count()
    scheduled = Post.query.filter_by(user_id=current_user.id, status='scheduled').count()
    failed = Post.query.filter_by(user_id=current_user.id, status='failed').count()
    accounts = SocialAccount.query.filter_by(user_id=current_user.id, is_active=True).count()
    
    return jsonify({
        'total_posts': total_posts,
        'published': published,
        'scheduled': scheduled,
        'failed': failed,
        'connected_accounts': accounts
    })

# ==================== SCHEDULER ====================

def check_scheduled_posts():
    with app.app_context():
        now = datetime.utcnow()
        posts = Post.query.filter(
            Post.status == 'scheduled',
            Post.scheduled_time <= now
        ).all()
        
        for post in posts:
            publish_to_social(post, post.user_id)

# ==================== INICIALIZACIÓN ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'version': '1.1.0'})

# Crear tablas al iniciar
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    scheduler.add_job(check_scheduled_posts, 'interval', minutes=1)
    scheduler.start()
    
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_DEBUG', 'False') == 'True')
