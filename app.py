from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from sqlalchemy import or_
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, DateTimeField, DateField, SelectField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'AJ94c36aUhnp5ACooY7X6kIc4qgVubLY'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='user', lazy=True)
    ride_options = db.relationship('RideOption', backref='user', lazy=True)

    def get_id(self):
        return str(self.sno)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.sno'), nullable=False)
    content = db.Column(db.String(250), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    reply_to = db.Column(db.Integer, db.ForeignKey('message.id'))
    replies = db.relationship('Message', backref=db.backref('parent', remote_side=[id]))
    message_type = db.Column(db.String(50))  # Rename 'type' to 'message_type'

    def __init__(self, sender_id, content, message_type=None, reply_to=None):
        self.sender_id = sender_id
        self.content = content
        self.message_type = message_type
        self.reply_to = reply_to

class RideOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.sno'), nullable=False)
    passengers = db.Column(db.Integer, nullable=False)
    starting_point = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    starting_time = db.Column(db.Time, nullable=False)
    mode_of_transport = db.Column(db.String(50), nullable=False)
    cost = db.Column(db.Integer, nullable=False)  # Added cost field
    is_accepted = db.Column(db.Boolean, default=False)

    def __init__(self, user_id, passengers, starting_point, destination, start_date, starting_time, mode_of_transport, cost):
        self.user_id = user_id
        self.start_date = start_date
        self.passengers = passengers
        self.starting_point = starting_point
        self.destination = destination
        self.starting_time = starting_time
        self.mode_of_transport = mode_of_transport
        self.cost = cost


ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'

class Questions(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(250), nullable=False, unique=True)
    year = db.Column(db.Integer, nullable=True)
    topic = db.Column(db.String(300))


class PostRideForm(FlaskForm):
    passengers = IntegerField('Passengers', validators=[DataRequired()])
    starting_point = StringField('Starting Point', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    start_time = DateTimeField('Start Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    mode_of_transport = SelectField('Mode of Transport', choices=[('auto', 'Auto'), ('car', 'Car'), ('van', 'Van'), ('bike', 'Bike')], validators=[DataRequired()])
    cost = IntegerField('Cost', validators=[DataRequired()])



with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Incorrect username or password!')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. You are not an admin.')
        return redirect(url_for('home'))

    if request.method == 'POST':
        question_text = request.form.get('question_text')
        year = request.form.get('year')
        topic = request.form.get('topic')

        new_question = Questions(question=question_text, year=year, topic=topic)
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!')

    return render_template('admin_dashboard.html')

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        target_word = request.form.get('target_word')
        search_results = Questions.query.filter(or_(Questions.question.ilike(f"%{target_word}%"),
                                                     Questions.topic.ilike(f"%{target_word}%"))).all()

        return render_template('home.html', search_results=search_results)

    return render_template('home.html', search_results=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('User already exists!')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        if username == ADMIN_USERNAME:
            new_user.is_admin = True
        db.session.add(new_user)
        db.session.commit()

    return render_template('register.html')

@app.route('/rides', methods=['GET'])
@login_required
def show_rides():
    # Fetch all posted rides from the database
    rides = RideOption.query.all()
    return render_template('rides.html', rides=rides)

@app.route('/respond/<int:ride_id>', methods=['POST'])
@login_required
def respond_to_ride(ride_id):
    ride_option = RideOption.query.get(ride_id)

    if ride_option and not ride_option.is_accepted and ride_option.passengers > 0:
        # Decrease the number of passengers by one
        ride_option.passengers -= 1

        # Add logic to handle the response (e.g., mark as accepted, create chat room, etc.)
        ride_option.is_accepted = True

        db.session.commit()

        flash('Ride responded successfully!')
    else:
        flash('Invalid ride response or no available seats.')

    return redirect(url_for('show_rides'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', current_user=current_user)

@app.route('/post_ride', methods=['GET', 'POST'])
@login_required
def post_ride():
    form = PostRideForm()

    if form.validate_on_submit():
        passengers = form.passengers.data
        starting_point = form.starting_point.data
        destination = form.destination.data
        start_time = form.start_time.data
        start_date = form.start_date.data
        mode_of_transport = form.mode_of_transport.data
        cost = form.cost.data

        ride_option = RideOption(
            user_id=current_user.sno,
            passengers=passengers,
            starting_point=starting_point,
            destination=destination,
            start_time=start_time,
            start_date=start_date,
            mode_of_transport=mode_of_transport,
            cost=cost
        )

        db.session.add(ride_option)
        db.session.commit()

        return render_template('post_ride.html', form=form, success_message='Ride posted successfully!')

    return render_template('post_ride.html', form=form)

@socketio.on('join')
def handle_join():
    join_room('chat_room')
    emit_previous_messages()

def emit_previous_messages():
    messages = Message.query.order_by(Message.timestamp).all()
    formatted_messages = [{
        'sender': message.user.username,
        'content': message.content,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for message in messages]
    emit('previous_messages', {'messages': formatted_messages}, room='chat_room')

@socketio.on('leave')
def handle_leave():
    leave_room('chat_room')
    emit('message', {'content': f'{current_user.username} has left the chat room.'}, room='chat_room')

@socketio.on('message')
def handle_message(data):
    if 'type' in data:
        if data['type'] == 'reply' and data['reply_to'] is not None:
            parent_message = Message.query.get(data['reply_to'])
            if parent_message:
                new_reply = Message(sender_id=current_user.sno, content=data['content'], reply_to=parent_message.id)
                db.session.add(new_reply)
                db.session.commit()

                emit('message', {
                    'sender': current_user.username,
                    'content': data['content'],
                    'timestamp': new_reply.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'reply',  # Set the type to 'reply' for the replied message
                    'reply_to': parent_message.id
                }, room='chat_room')
            else:
                emit('error', {'message': 'Parent message not found'}, room=request.sid)
        elif data['type'] != 'reply':
            new_message = Message(sender_id=current_user.sno, content=data['content'], message_type=data['type'])
            db.session.add(new_message)
            db.session.commit()

            reply_button = ''
            if data['type'] == 'request':
                reply_button = f'<span class="reply-btn" onclick="replyToMessage(\'{current_user.username}\', \'{data["content"]}\')">Reply</span>'

            emit('message', {
                'sender': current_user.username,
                'content': data['content'],
                'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'type': data['type'],
                'replyBtn': reply_button
            }, room='chat_room')
        else:
            emit('error', {'message': 'Invalid reply data'}, room=request.sid)

if __name__ == "__main__":
    socketio.run(app, port=1908, debug=True)
