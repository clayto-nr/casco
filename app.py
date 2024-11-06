from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/minhabasededados'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Desativa o rastreamento de modificações
db = SQLAlchemy(app)

# Modelo de usuário
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    senha = db.Column(db.String(150), nullable=False)

# Criação automática das tabelas
with app.app_context():
    db.create_all()

# Rota de registro
@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        senha = request.form['senha']
        
        # Verificar se o usuário já existe
        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('Email já registrado! Tente outro.', 'danger')
            return redirect(url_for('registrar'))
        
        # Hash da senha
        hashed_senha = generate_password_hash(senha, method='sha256')
        novo_usuario = Usuario(username=username, email=email, senha=hashed_senha)
        
        # Adicionar novo usuário ao banco de dados
        db.session.add(novo_usuario)
        db.session.commit()
        flash('Registrado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('registrar.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        
        # Verificar credenciais
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario and check_password_hash(usuario.senha, senha):
            session['user_id'] = usuario.id
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou senha incorretos.', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Você precisa fazer login primeiro!', 'warning')
        return redirect(url_for('login'))
    
    # Recuperar os dados do usuário logado
    usuario = Usuario.query.get(session['user_id'])
    
    # Verificar se o usuário existe
    if not usuario:
        flash('Usuário não encontrado!', 'danger')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', usuario=usuario)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Deslogado com sucesso!', 'success')
    return redirect(url_for('login'))

@app.route('/me')
def me():
    if 'user_id' not in session:
        flash('Você precisa estar logado para ver seus dados!', 'warning')
        return redirect(url_for('login'))
    
    # Recuperar os dados do usuário logado
    usuario = Usuario.query.get(session['user_id'])
    
    # Verificar se o usuário existe
    if not usuario:
        flash('Usuário não encontrado!', 'danger')
        return redirect(url_for('login'))
    
    return render_template('me.html', usuario=usuario)

# Nova rota para acessar dados do usuário logado em formato JSON
@app.route('/api/me', methods=['GET'])
def api_me():
    if 'user_id' not in session:
        return jsonify({"error": "Você precisa estar logado para ver seus dados!"}), 403
    
    # Recuperar os dados do usuário logado
    usuario = Usuario.query.get(session['user_id'])
    
    # Verificar se o usuário existe
    if not usuario:
        return jsonify({"error": "Usuário não encontrado!"}), 404
    
    # Retornar os dados em formato JSON
    return jsonify({
        "username": usuario.username,
        "email": usuario.email,
        "id": usuario.id
    })

if __name__ == '__main__':
    app.run(debug=True)
