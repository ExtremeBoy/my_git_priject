from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import paramiko
import os
import signal

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change_me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webui.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class Router(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    host = db.Column(db.String(120))
    ssh_user = db.Column(db.String(80))
    ssh_port = db.Column(db.Integer, default=22)
    local_port = db.Column(db.Integer)       # local port for tunnel
    remote_port = db.Column(db.Integer)      # remote forwarded port
    autossh_pid = db.Column(db.Integer)

def init_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password_hash=generate_password_hash('admin'))
        db.session.add(admin)
        db.session.commit()

@app.before_first_request
def setup():
    db.create_all()
    init_admin()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    routers = Router.query.all()
    return render_template('index.html', routers=routers)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/routers/add', methods=['GET', 'POST'])
def add_router():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        router = Router(
            name=request.form['name'],
            host=request.form['host'],
            ssh_user=request.form['ssh_user'],
            ssh_port=int(request.form.get('ssh_port', 22)),
            local_port=int(request.form['local_port']),
            remote_port=int(request.form['remote_port'])
        )
        db.session.add(router)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_router.html')

@app.route('/routers/<int:router_id>/start')
def start_router(router_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    router = Router.query.get_or_404(router_id)
    if router.autossh_pid:
        return redirect(url_for('index'))
    cmd = [
        'autossh', '-M', '0', '-N', '-f',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-R', f"{router.remote_port}:localhost:{router.local_port}",
        f"{router.ssh_user}@{router.host}",
        '-p', str(router.ssh_port)
    ]
    proc = subprocess.Popen(cmd)
    router.autossh_pid = proc.pid
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/routers/<int:router_id>/stop')
def stop_router(router_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    router = Router.query.get_or_404(router_id)
    if router.autossh_pid:
        try:
            os.kill(router.autossh_pid, signal.SIGTERM)
        except OSError:
            pass
        router.autossh_pid = None
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/monitor/<int:router_id>')
def monitor(router_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    router = Router.query.get_or_404(router_id)
    return render_template('monitor.html', router=router)

@app.route('/api/metrics/<int:router_id>')
def metrics(router_id):
    router = Router.query.get_or_404(router_id)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(router.host, port=router.ssh_port, username=router.ssh_user)
        stdin, stdout, stderr = ssh.exec_command('cat /proc/loadavg')
        loadavg = stdout.read().decode().strip()
        ssh.close()
        return jsonify({'loadavg': loadavg})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
