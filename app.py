from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/douglas'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Desativa o rastreamento de modificações
db = SQLAlchemy(app)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    senha = db.Column(db.String(150), nullable=False)
    tipo = db.Column(db.String(20), nullable=False, default='participante')  # Tipo de usuário: lider ou participante
    admin = db.Column(db.Boolean, default=False)  # Permissão de administrador

class Equipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    lider_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    lider = db.relationship('Usuario', backref='equipes')


# Criação automática das tabelas
with app.app_context():
    db.create_all()


@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        senha = request.form['senha']
        
        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('Email já registrado! Tente outro.', 'danger')
            return redirect(url_for('registrar'))
        
        hashed_senha = generate_password_hash(senha, method='sha256')
        novo_usuario = Usuario(username=username, email=email, senha=hashed_senha, tipo='participante', admin=False)
        
        db.session.add(novo_usuario)
        db.session.commit()
        flash('Registrado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('registrar.html')

# Rota de login
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

# Rota do dashboard
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

# Rota de logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Deslogado com sucesso!', 'success')
    return redirect(url_for('login'))

# Rota para exibir dados do usuário logado
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

# Rota para gerenciar usuários
@app.route('/gerenciar_usuarios', methods=['GET', 'POST'])
def gerenciar_usuarios():
    if 'user_id' not in session:
        flash('Você precisa fazer login primeiro!', 'warning')
        return redirect(url_for('login'))
    
    # Apenas usuários administradores podem acessar a gestão de usuários
    usuario_logado = Usuario.query.get(session['user_id'])
    print(f"Usuário logado: {usuario_logado.username}, Admin: {usuario_logado.admin}")  # Debug
    if not usuario_logado.admin:
        flash('Acesso negado: Permissões de administrador são necessárias!', 'danger')
        return redirect(url_for('dashboard'))
    # Atualização de tipo ou permissão de um usuário
    if request.method == 'POST':
        user_id = request.form['user_id']
        tipo = request.form['tipo']
        admin = True if request.form.get('admin') == 'on' else False
        
        usuario = Usuario.query.get(user_id)
        if usuario:
            usuario.tipo = tipo
            usuario.admin = admin
            db.session.commit()
            flash(f'Permissões de {usuario.username} atualizadas com sucesso!', 'success')
    
    usuarios = Usuario.query.all()
    return render_template('gerenciar_usuarios.html', usuarios=usuarios)

# Rota para deletar um usuário
@app.route('/deletar_usuario/<int:id>', methods=['POST'])
def deletar_usuario(id):
    if 'user_id' not in session:
        flash('Você precisa fazer login primeiro!', 'warning')
        return redirect(url_for('login'))
    
    # Buscar o usuário pelo ID
    usuario = Usuario.query.get(id)
    
    if not usuario:
        flash('Usuário não encontrado!', 'danger')
        return redirect(url_for('gerenciar_usuarios'))
    
    # Remover o usuário do banco de dados
    db.session.delete(usuario)
    db.session.commit()
    flash(f'Usuário {usuario.username} foi deletado com sucesso!', 'success')
    return redirect(url_for('gerenciar_usuarios'))

@app.route('/criar_equipe', methods=['GET', 'POST'])
def criar_equipe():
    if 'user_id' not in session:
        flash('Você precisa fazer login primeiro!', 'warning')
        return redirect(url_for('login'))
    
    usuario = Usuario.query.get(session['user_id'])
    
    # Verificar se o usuário é líder (admin)
    if not usuario.admin:
        flash('Apenas líderes podem criar equipes!', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        nome = request.form['nome']
        
        # Verificar se o nome da equipe já existe
        equipe_existente = Equipe.query.filter_by(nome=nome).first()
        if equipe_existente:
            flash('Já existe uma equipe com esse nome!', 'danger')
            return redirect(url_for('criar_equipe'))
        
        # Criar a nova equipe
        nova_equipe = Equipe(nome=nome, lider_id=usuario.id)
        db.session.add(nova_equipe)
        db.session.commit()
        
        flash(f'Equipe "{nome}" criada com sucesso!', 'success')
        return redirect(url_for('listar_equipes'))
    
    return render_template('criar_equipe.html')

@app.route('/minhas_equipes', methods=['GET', 'POST'])
def minhas_equipes():
    if 'user_id' not in session:
        flash('Você precisa fazer login primeiro!', 'warning')
        return redirect(url_for('login'))
    
    usuario = Usuario.query.get(session['user_id'])
    
    # Verificar se o usuário é líder (admin)
    if not usuario.admin:
        flash('Apenas líderes podem acessar essa página!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Se o método for POST, o usuário está tentando criar uma nova equipe
    if request.method == 'POST':
        nome = request.form['nome']
        
        # Verificar se o nome da equipe já existe
        equipe_existente = Equipe.query.filter_by(nome=nome).first()
        if equipe_existente:
            flash('Já existe uma equipe com esse nome!', 'danger')
        else:
            # Criar a nova equipe
            nova_equipe = Equipe(nome=nome, lider_id=usuario.id)
            db.session.add(nova_equipe)
            db.session.commit()
            flash(f'Equipe "{nome}" criada com sucesso!', 'success')
    
    # Buscar as equipes que o líder criou
    equipes = Equipe.query.filter_by(lider_id=usuario.id).all()
    
    return render_template('minhas_equipes.html', equipes=equipes)

# Executar o app
if __name__ == '__main__':
    app.run(debug=True)
