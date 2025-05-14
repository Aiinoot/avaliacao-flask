from flask import Flask, render_template, request, redirect, session, flash, url_for, g
import re
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

import sqlite3

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'


def init_db():
    with sqlite3.connect('instance/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT,
                email TEXT UNIQUE,
                celular TEXT,
                senha TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contatos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                nome TEXT,
                email TEXT,
                celular TEXT,
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mensagens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                contato_id INTEGER,
                titulo TEXT NOT NULL,
                texto TEXT NOT NULL,
                data_envio TEXT NOT NULL,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
                FOREIGN KEY (contato_id) REFERENCES contatos(id)
               )
        ''')
        conn.commit()

@app.before_request
def before_request():
    user_id = session.get('user_id')
    if user_id:
        with sqlite3.connect('instance/database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nome, email FROM usuarios WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if user:
                g.user = {'name': user[0], 'email': user[1]}
            else:
                g.user = None
    else:
        g.user = None

def inject_user():
    return {'user': g.user}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form['nome'].strip()
        email = request.form['email'].strip()
        celular = request.form['celular'].strip()
        senha = request.form['senha']
        confirmar = request.form['confirmar']

        if not nome or not email or not celular or not senha or not confirmar:
            flash('Todos os campos são obrigatórios.')
            return render_template('register.html', nome=nome, email=email, celular=celular)

        def email_valido(email):
            return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)
        
        if not email_valido(email):
            flash('E-mail inválido.')
            return render_template('register.html', nome=nome, email=email, celular=celular)

        if senha != confirmar:
            flash('As senhas não coincidem.')
            return render_template('register.html', nome=nome, email=email, celular=celular)

        with sqlite3.connect('instance/database.db') as conn:
            cursor = conn.cursor()
            try:
                senha_hash = generate_password_hash(senha)
                cursor.execute('INSERT INTO usuarios (nome, email, celular, senha) VALUES (?, ?, ?, ?)',
                              (nome, email, celular, senha_hash))
                conn.commit()
                flash('Cadastro realizado com sucesso. Faça login.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email já cadastrado.')
                return render_template('register.html', nome=nome, email=email, celular=celular)

    return render_template('register.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        senha = request.form['senha']

        if not email or not senha:
            flash('Preencha todos os campos.')
            return redirect(url_for('login'))

        with sqlite3.connect('instance/database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nome, email, senha FROM usuarios WHERE email = ?', (email,))
            user = cursor.fetchone()
            if not user:
                flash('Usuário não encontrado.')
            elif not check_password_hash(user[3], senha):
                flash('Senha incorreta.')
            else:

                session['user_id'] = user[0]
                session['user_name'] = user[1]
                session['user_email'] = user[2]
                flash('Login realizado com sucesso.')
                return redirect(url_for('dashboard'))

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout realizado.')
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with sqlite3.connect('instance/database.db') as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT nome, email FROM usuarios WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()

        if not user_data:
            return redirect(url_for('logout'))

        user = {
            'name': user_data[0],
            'email': user_data[1]
        }

        cursor.execute('SELECT id, nome, email, celular FROM contatos WHERE usuario_id = ?', (user_id,))
        contatos = cursor.fetchall()

        cursor.execute('''
            SELECT id, titulo, data_envio
            FROM mensagens
            WHERE usuario_id = ?
            ORDER BY data_envio DESC
        ''', (user_id,))
        mensagens = cursor.fetchall()

    return render_template('dashboard.html',
        user=user,  
        contatos=[{
            'id': c[0],
            'nome': c[1],
            'email': c[2],
            'celular': c[3]
        } for c in contatos],
        mensagens=[{
            'id': m[0],
            'assunto': m[1],
            'data': m[2],
            'status': 'Enviado'
        } for m in mensagens]
    )



@app.route('/contatos', methods=['GET'])
def contatos():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    with sqlite3.connect('instance/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, nome FROM usuarios WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()

    if user_data is None:
        return redirect(url_for('logout'))

    user = {
        'id': user_data[0],
        'name': user_data[1]
    }

    cursor.execute('SELECT id, nome, email, celular FROM contatos WHERE usuario_id = ?', (user_id,))
    contatos = cursor.fetchall()

    return render_template('contatos.html', user=user, contatos=contatos)


@app.route('/contato', methods=['GET', 'POST'])
def criar_contato():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        nome = request.form['nome'].strip()
        email = request.form['email'].strip()
        celular = request.form['celular'].strip()

        if not nome or not email or not celular:
            flash('Todos os campos devem ser preenchidos.')
            return render_template('create_contact.html', nome=nome, email=email, celular=celular)

        def email_valido(email):
            return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

        if not email_valido(email):
            flash('E-mail inválido.')
            return render_template('create_contact.html', nome=nome, email=email, celular=celular)

        with sqlite3.connect('instance/database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO contatos (usuario_id, nome, email, celular) VALUES (?, ?, ?, ?)',
                           (user_id, nome, email, celular))
            conn.commit()

        flash('Contato cadastrado com sucesso.')
        return redirect(url_for('contatos'))

    return render_template('create_contact.html')


@app.route('/editar_contato/<int:contato_id>', methods=['GET', 'POST'])
def editar_contato(contato_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('instance/database.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        nome = request.form['nome'].strip()
        email = request.form['email'].strip()
        celular = request.form['celular'].strip()

        if not nome or not email or not celular:
            flash('Todos os campos são obrigatórios.')
            return render_template('edit_contatc.html', contato_id=contato_id, nome=nome, email=email, celular=celular)

        cursor.execute('''
            UPDATE contatos
            SET nome = ?, email = ?, celular = ?
            WHERE id = ? AND usuario_id = ?
        ''', (nome, email, celular, contato_id, user_id))
        conn.commit()
        conn.close()
        flash('Contato atualizado com sucesso.')
        return redirect(url_for('contatos'))
    
    user_id = session['user_id']
    cursor.execute('SELECT nome, email, celular FROM contatos WHERE id = ? AND usuario_id = ?', (contato_id, user_id))
    contato = cursor.fetchone()
    conn.close()

    if not contato:
        flash('Contato não encontrado.')
        return redirect(url_for('dashboard'))

    return render_template('edit_contact.html', contato_id=contato_id, nome=contato[0], email=contato[1], celular=contato[2])

@app.route('/excluir_contato/<int:contato_id>')
def excluir_contato(contato_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with sqlite3.connect('instance/database.db')as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM contatos WHERE id = ? AND usuario_id = ?', (contato_id, user_id))
        conn.commit()
    flash('Contato excluído com sucesso.')
    return redirect(url_for('contatos'))

@app.route('/mensagem', methods=['GET', 'POST'])
def mensagem():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with sqlite3.connect('instance/database.db')as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, nome FROM contatos WHERE usuario_id = ?', (user_id,))
        contatos = cursor.fetchall()

    if request.method == 'POST':
        contato_id = request.form['contato_id']
        titulo = request.form['titulo'].strip()
        texto = request.form['texto'].strip()
        data_envio = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not titulo or not texto or not contato_id:
            flash('Todos os campos são obrigatórios.')
            return render_template('mensagem.html', contatos=contatos, titulo=titulo, texto=texto)

        with sqlite3.connect('instance/database.db')as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO mensagens (usuario_id, contato_id, titulo, texto, data_envio)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, contato_id, titulo, texto, data_envio))
            conn.commit()
            flash('Mensagem enviada com sucesso.')
            return redirect(url_for('mensagens'))

    return render_template('mensagem.html', contatos=contatos)

@app.route('/mensagens')
def mensagens():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with sqlite3.connect('instance/database.db') as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT nome, email FROM usuarios WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()

        if not user_data:
            return redirect(url_for('logout'))

        user = {
            'name': user_data[0],
            'email': user_data[1]
        }

        cursor.execute('''
            SELECT mensagens.id, mensagens.titulo, mensagens.texto, mensagens.data_envio, contatos.nome
            FROM mensagens
            JOIN contatos ON mensagens.contato_id = contatos.id
            WHERE mensagens.usuario_id = ?
            ORDER BY mensagens.data_envio DESC
        ''', (user_id,))
        mensagens = cursor.fetchall()

    return render_template('mensagens.html', user=user, mensagens=mensagens)


@app.route('/editar_mensagem/<int:id>', methods=['GET', 'POST'])
def editar_mensagem(id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    conn = sqlite3.connect('instance/database.db')
    cursor = conn.cursor()

    cursor.execute('SELECT titulo, texto, contato_id FROM mensagens WHERE id = ? AND usuario_id = ?', (id, user_id))
    mensagem = cursor.fetchone()

    if not mensagem:
        conn.close()
        return 'Mensagem não encontrada ou acesso não autorizado.', 403

    if request.method == 'POST':
        titulo = request.form['titulo']
        texto = request.form['texto']
        cursor.execute('''
            UPDATE mensagens SET titulo = ?, texto = ?
            WHERE id = ? AND usuario_id = ?
        ''', (titulo, texto, id, user_id))
        conn.commit()
        conn.close()
        return redirect('/mensagens')

    cursor.execute('SELECT id, nome FROM contatos WHERE usuario_id = ?', (user_id,))
    contatos = cursor.fetchall()
    conn.close()
    return render_template('mensagem.html', titulo=mensagem[0], texto=mensagem[1], contatos=contatos)

@app.route('/mensagem/<int:mensagem_id>')
def visualizar_mensagem(mensagem_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with sqlite3.connect('instance/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT titulo, texto, data_envio, contato_id
            FROM mensagens
            WHERE id = ? AND usuario_id = ?
        ''', (mensagem_id, user_id))
        mensagem = cursor.fetchone()

        if not mensagem:
            flash('Mensagem não encontrada.')
            return redirect(url_for('dashboard'))

    return render_template('mensagem.html', titulo=mensagem[0], texto=mensagem[1], contatos=[], visualizar=True)


@app.route('/excluir_mensagem/<int:id>', methods=['POST'])
def excluir_mensagem(id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    conn = sqlite3.connect('instance/database.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM mensagens WHERE id = ? AND usuario_id = ?', (id, user_id))
    if cursor.fetchone() is None:
        conn.close()
        return 'Mensagem não encontrada ou acesso não autorizado.', 403

    cursor.execute('DELETE FROM mensagens WHERE id = ? AND usuario_id = ?', (id, user_id))
    conn.commit()
    conn.close()
    return redirect('/mensagens')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
