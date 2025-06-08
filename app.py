import psycopg2
from flask import session, Flask, render_template, request, redirect, url_for, jsonify, flash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)
from datetime import timedelta
import logging


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Для сессий (если планируешь использовать сессии)

# Конфигурация JWT
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Лучше через переменные окружения
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'
app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token_cookie'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_COOKIE_SECURE'] = False  # True на HTTPS
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False


#app.config['JWT_COOKIE_SECURE'] = True  
#app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
#app.config['JWT_REFRESH_COOKIE_PATH'] = '/'
#app.config['JWT_COOKIE_CSRF_PROTECT'] = True  


jwt = JWTManager(app)


# Логирование ошибок
logging.basicConfig(
    filename='error.log',
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Настройки БД
DB_HOST = "localhost"
DB_NAME = "schema"
DB_USER = "postgres"
DB_PASS = "root"

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True, locations=["cookies"])
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)

    resp = jsonify({'msg': 'Токен обновлён'})
    set_access_cookies(resp, access_token)
    return resp


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.is_json:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
    else:
        email = request.form.get('email')
        password = request.form.get('password')

    if not email or not password:
        if request.is_json:
            return jsonify({'msg': 'Email и пароль обязательны'}), 400
        flash('Email и пароль обязательны', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, password FROM users WHERE email = %s;', (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user[1], password):
            access_token = create_access_token(identity=str(user[0]))
            refresh_token = create_refresh_token(identity=str(user[0]))

            if request.is_json:
                resp = jsonify({'msg': 'Успешный вход', 'access_token': access_token})
                set_access_cookies(resp, access_token)
                set_refresh_cookies(resp, refresh_token)
                return resp
            else:
                resp = redirect(url_for('home'))
                set_access_cookies(resp, access_token)
                set_refresh_cookies(resp, refresh_token)
                return resp
        else:
            if request.is_json:
                return jsonify({'msg': 'Неверный логин или пароль'}), 401
            flash('Неверный логин или пароль', 'error')
            return redirect(url_for('login'))

    finally:
        cursor.close()
        conn.close()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if not all([username, email, password]):
        flash('Все поля обязательны', 'error')
        return redirect(url_for('register'))

    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s) RETURNING id;',
            (username, email, hashed_password, 'participant')
        )
        user_id = cursor.fetchone()[0]
        conn.commit()

        access_token = create_access_token(identity=str(user_id))
        refresh_token = create_refresh_token(identity=str(user_id))

        resp = redirect(url_for('login'))
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        return resp
    except psycopg2.IntegrityError:
        conn.rollback()
        flash('Пользователь с таким email уже существует', 'error')
        return redirect(url_for('register'))
    except Exception as e:
        conn.rollback()
        flash(f'Ошибка регистрации: {str(e)}', 'error')
        return redirect(url_for('register'))
    finally:
        cursor.close()
        conn.close()


@app.route('/')
def home():
    return redirect(url_for('login'))

# Пример, как защитить страницу с JWT
@app.route('/events', methods=['GET'])
@jwt_required()
def events():
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM internal_events;')
    events = cursor.fetchall()

    event_list = []
    for event in events:
        event_dict = {
            'event': {
                'id': event[0],
                'title': event[1],
                'date': event[2],
                'description': event[3],
                'name': event[4],
                'location': event[5]
            }
        }
        cursor.execute('SELECT * FROM incidents WHERE event_id = %s;', (event[0],))
        incidents = cursor.fetchall()
        event_dict['incidents'] = [{'id': i[0], 'name': i[1], 'date': i[2]} for i in incidents]
        event_list.append(event_dict)

    cursor.close()
    conn.close()
    return render_template('events.html', events_with_incidents_risks=event_list)

@app.route('/events/add', methods=['POST'])
@jwt_required()
def add_event():

    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()

    title = request.form.get('title')
    date = request.form.get('date')
    description = request.form.get('description', '')
    name = request.form.get('name')
    location = request.form.get('location')

    if not title or not date or not name or not location:
        return "Ошибка: все обязательные поля должны быть заполнены", 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO internal_events (title, date, description, name, location) VALUES (%s, %s, %s, %s, %s);',
            (title, date, description, name, location)
        )
        conn.commit()
        return redirect(url_for('events'))
    except Exception as e:
        conn.rollback()
        return f"Ошибка при добавлении мероприятия: {str(e)}", 500
    finally:
        cursor.close()
        conn.close()


@app.route('/events/edit/<int:event_id>', methods=['GET', 'PUT'])
@jwt_required()
def edit_event(event_id):
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Обработка PUT-запроса
        if request.method == 'PUT':
            data = request.get_json()  # Получаем данные из JSON
            title = data.get('title')
            date = data.get('date')
            description = data.get('description')
            name = data.get('name')
            location = data.get('location')

            cursor.execute(
                '''
                UPDATE internal_events
                SET title = %s, date = %s, description = %s, name = %s, location = %s
                WHERE id = %s;
                ''',
                (title, date, description, name, location, event_id)
            )
            conn.commit()

            return {'message': 'Мероприятие успешно обновлено'}, 200

        # Обработка GET-запроса для получения данных мероприятия
        cursor.execute('SELECT * FROM internal_events WHERE id = %s;', (event_id,))
        event = cursor.fetchone()

        if not event:
            return 'Мероприятие не найдено', 404

        return render_template('edit_event.html', event=event)

    except Exception as e:
        return str(e), 500

    finally:
        cursor.close()
        conn.close()



@app.route('/events/delete/<int:event_id>', methods=['DELETE'])
@jwt_required()
def delete_event(event_id):
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Выполняем удаление мероприятия
        cursor.execute('DELETE FROM internal_events WHERE id = %s;', (event_id,))
        conn.commit()

        return '', 204  # Успешное удаление без содержимого

    except Exception as e:
        conn.rollback()
        return f"Ошибка при удалении мероприятия: {str(e)}", 500

    finally:
        cursor.close()
        conn.close()



# Страница инцидентов
@app.route('/incidents')
@jwt_required()
def incidents():

    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Получаем инциденты с информацией о мероприятии
        cursor.execute("""
            SELECT i.id, i.incident_name, i.description, i.severity, i.timestamp, e.title, e.name
            FROM incidents i
            JOIN internal_events e ON i.event_id = e.id
        """)
        incidents = cursor.fetchall()

        cursor.close()
        conn.close()

        # Преобразуем кортежи в словари или объекты, если нужно
        incidents_data = [{
            'id': incident[0],
            'incident_name': incident[1],
            'description': incident[2],
            'severity': incident[3],
            'timestamp': incident[4],  # предполагаем, что timestamp — это datetime
            'event': {'name': incident[6]}  # теперь добавляем event.name для получения названия мероприятия
        } for incident in incidents]

        return render_template('incidents.html', incidents=incidents_data)

    except Exception as e:
        print(f"Ошибка: {e}")
        return render_template('incidents.html', incidents=[])

# Страница для добавления инцидента
@app.route('/incidents/add', methods=['GET', 'POST'])
@jwt_required()
def add_incident():
    user_id = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        is_json = request.is_json
        data = request.get_json() if is_json else request.form

        incident_name = data.get('incident_name')
        description = data.get('description')
        severity = data.get('severity')
        event_id = data.get('event_id')

        print(f"Получены данные: {incident_name}, {description}, {severity}, {event_id}")

        if not incident_name or not description or not severity or not event_id:
            msg = "Все поля обязательны для заполнения"
            print("Ошибка: не все поля заполнены")
            if is_json:
                return jsonify({"error": msg}), 400
            else:
                flash(msg, "error")
                return redirect(url_for('add_incident'))

        try:
            cursor.execute('SELECT id FROM internal_events WHERE id = %s', (event_id,))
            event = cursor.fetchone()

            if not event:
                msg = f"Мероприятие с id {event_id} не найдено"
                print("Ошибка:", msg)
                if is_json:
                    return jsonify({"error": msg}), 404
                else:
                    flash("Выбранное мероприятие не существует.", "error")
                    return redirect(url_for('add_incident'))

            cursor.execute(
                'INSERT INTO incidents (incident_name, description, severity, event_id) VALUES (%s, %s, %s, %s);',
                (incident_name, description, severity, event_id)
            )
            conn.commit()
            print("Инцидент успешно добавлен в базу данных.")

            if is_json:
                return jsonify({"message": "Инцидент успешно добавлен"}), 200
            else:
                flash("Инцидент успешно добавлен.", "success")
                return redirect(url_for('incidents'))

        except Exception as e:
            print("Ошибка при добавлении инцидента:", e)
            if is_json:
                return jsonify({"error": str(e)}), 500
            else:
                flash(f"Ошибка при добавлении инцидента: {e}", "error")
                return redirect(url_for('add_incident'))

    # GET-запрос: отображаем форму
    try:
        cursor.execute('SELECT * FROM internal_events;')
        internal_events = cursor.fetchall()
        return render_template('add_incident.html', internal_events=internal_events)
    except Exception as e:
        print("Ошибка при получении мероприятий:", e)
        flash(f"Ошибка при получении данных мероприятий: {e}", "error")
        return redirect(url_for('incidents'))
    finally:
        cursor.close()
        conn.close()

# Функция для получения всех мероприятий
def get_all_events():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM internal_events;')
    events = cursor.fetchall()
    cursor.close()
    conn.close()
    return events


# Редактирование инцидента
@app.route('/incidents/edit/<int:incident_id>', methods=['GET', 'PUT'])
@jwt_required()
def edit_incident(incident_id):
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'PUT':
        data = request.json  # Получаем JSON из тела запроса

        incident_name = data.get('incident_name')
        description = data.get('description')
        severity = data.get('severity')
        event_id = data.get('event_id')

        if not incident_name or not description or not severity or not event_id:
            cursor.close()
            conn.close()
            return jsonify({"msg": "Все поля обязательны для заполнения"}), 400

        try:
            cursor.execute(
                'UPDATE incidents SET incident_name = %s, description = %s, severity = %s, event_id = %s WHERE id = %s;',
                (incident_name, description, severity, event_id, incident_id)
            )
            conn.commit()
        except Exception as e:
            cursor.close()
            conn.close()
            return jsonify({"msg": f"Ошибка при редактировании инцидента: {e}"}), 500

        cursor.close()
        conn.close()
        return jsonify({"msg": "Инцидент успешно обновлен"}), 200

    # GET запрос — отдаем страницу редактирования
    cursor.execute('SELECT * FROM incidents WHERE id = %s;', (incident_id,))
    incident = cursor.fetchone()

    cursor.execute('SELECT * FROM internal_events;')
    internal_events = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('edit_incident.html', incident=incident, internal_events=internal_events)

# Удаление инцидента
@app.route('/incidents/delete/<int:incident_id>', methods=['DELETE'])
@jwt_required()
def delete_incident(incident_id):
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM incidents WHERE id = %s;', (incident_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'msg': 'Инцидент удалён'}), 200


@app.route('/security_plans', methods=['GET', 'POST'])
@jwt_required()
def security_plans():
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':  # Добавление нового плана безопасности
        plan_name = request.form['plan_name']
        plan_description = request.form['plan_description']
        
        # Вставляем новый план безопасности
        cursor.execute('INSERT INTO security_plans (plan_name, plan_description) VALUES (%s, %s) RETURNING id', 
                       (plan_name, plan_description))
        plan_id = cursor.fetchone()[0]  # Получаем ID последней вставленной записи (план)

        conn.commit()
        print(f"Создан новый план безопасности с ID: {plan_id}")

        # Получаем список выбранных мероприятий (можно выбрать несколько)
        event_ids = request.form.getlist('event_ids')  # Получаем список ID выбранных мероприятий
        print(f"Выбранные мероприятия: {event_ids}")  # Выведем список для отладки

        if event_ids:
            for event_id in event_ids:
                # Убедимся, что event_id существует в базе данных
                cursor.execute('SELECT id FROM internal_events WHERE id = %s', (event_id,))
                event = cursor.fetchone()
                if event:
                    print(f"Мероприятие с ID {event_id} найдено, привязываем к плану безопасности")
                    # Привязываем выбранное мероприятие к плану безопасности
                    cursor.execute('INSERT INTO event_security_plans (event_id, security_plan_id) VALUES (%s, %s)', 
                                   (event_id, plan_id))
                    conn.commit()
                else:
                    print(f"Мероприятие с ID {event_id} не найдено")
                    flash(f"Мероприятие с ID {event_id} не найдено", "error")
        else:
            flash("Не выбрано мероприятие для привязки", "error")

        flash('План безопасности успешно добавлен!', 'success')
        return redirect(url_for('security_plans'))

    # Получаем список планов безопасности с привязанными мероприятиями
    cursor.execute("""
        SELECT sp.id, sp.plan_name, sp.plan_description, 
               string_agg(e.name, ', ') AS event_names
        FROM security_plans sp
        LEFT JOIN event_security_plans esp ON sp.id = esp.security_plan_id
        LEFT JOIN internal_events e ON esp.event_id = e.id
        GROUP BY sp.id;
    """)
    plans = cursor.fetchall()

    # Получаем список мероприятий для привязки
    cursor.execute('SELECT id, name FROM internal_events;')
    events = cursor.fetchall()

    cursor.close()
    conn.close()
    
    return render_template('security_plans.html', plans=plans, events=events)


@app.route('/edit_security_plan/<int:plan_id>', methods=['GET', 'POST'])
@jwt_required()
def edit_security_plan(plan_id):
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':  # Сохранение изменений плана безопасности
        plan_name = request.form['plan_name']
        plan_description = request.form['plan_description']
        event_ids = request.form.getlist('event_ids')  # Список выбранных мероприятий

        # Обновляем данные плана безопасности
        cursor.execute("""
            UPDATE security_plans
            SET plan_name = %s, plan_description = %s
            WHERE id = %s
        """, (plan_name, plan_description, plan_id))

        # Удаляем все старые связи с мероприятиями
        cursor.execute('DELETE FROM event_security_plans WHERE security_plan_id = %s', (plan_id,))

        # Создаем новые связи между планом и мероприятиями
        for event_id in event_ids:
            cursor.execute("""
                INSERT INTO event_security_plans (event_id, security_plan_id)
                VALUES (%s, %s)
            """, (event_id, plan_id))

        conn.commit()
        flash('План безопасности успешно обновлен!', 'success')
        return redirect(url_for('security_plans'))

    # Получаем текущие данные плана безопасности
    cursor.execute("""
        SELECT id, plan_name, plan_description
        FROM security_plans
        WHERE id = %s
    """, (plan_id,))
    plan = cursor.fetchone()

    # Получаем все мероприятия
    cursor.execute('SELECT id, name FROM internal_events;')
    events = cursor.fetchall()

    # Получаем уже привязанные мероприятия для текущего плана
    cursor.execute("""
        SELECT e.id, e.name
        FROM internal_events e
        JOIN event_security_plans esp ON e.id = esp.event_id
        WHERE esp.security_plan_id = %s
    """, (plan_id,))
    selected_events = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('edit_security_plan.html', plan=plan, events=events, selected_events=selected_events)


@app.route('/protected')
@jwt_required()
def protected():
    return "Только для авторизованных"


from flask import request

@app.route('/index')
@jwt_required()
def index():
    user_id = get_jwt_identity()

    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except ValueError:
        page = 1

    per_page = 5
    filter_name = request.args.get('filter_name', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Получаем список уникальных названий для селекта
        cursor.execute("SELECT DISTINCT name FROM internal_events ORDER BY name")
        unique_names = [row[0] for row in cursor.fetchall()]

        base_query = "SELECT * FROM internal_events WHERE TRUE"
        params = []

        if filter_name:
            base_query += " AND name = %s"
            params.append(filter_name)

        count_query = f"SELECT COUNT(*) FROM ({base_query}) AS subquery"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        total_pages = max((total_count + per_page - 1) // per_page, 1)

        offset = (page - 1) * per_page
        base_query += " ORDER BY date DESC LIMIT %s OFFSET %s"
        params.extend([per_page, offset])

        cursor.execute(base_query, params)
        events = cursor.fetchall()

        events_data = []
        for event in events:
            event_id = event[0]
            event_dict = {
                'id': event_id,
                'title': event[1],
                'date': event[2].strftime('%Y-%m-%d') if event[2] else '',
                'description': event[3],
                'name': event[4],
                'location': event[5],
                'incidents': [],
                'security_plans': []
            }

            cursor.execute(
                'SELECT id, incident_name, description, severity, timestamp FROM incidents WHERE event_id = %s ORDER BY timestamp DESC LIMIT 3',
                (event_id,)
            )
            incidents = cursor.fetchall()
            for inc in incidents:
                event_dict['incidents'].append({
                    'id': inc[0],
                    'name': inc[1],
                    'description': inc[2],
                    'severity': inc[3],
                    'timestamp': inc[4].strftime('%Y-%m-%d %H:%M:%S') if inc[4] else ''
                })

            cursor.execute("""
                SELECT sp.id, sp.plan_name, sp.plan_description
                FROM security_plans sp
                JOIN event_security_plans esp ON sp.id = esp.security_plan_id
                WHERE esp.event_id = %s
                LIMIT 2
            """, (event_id,))
            plans = cursor.fetchall()
            for plan in plans:
                event_dict['security_plans'].append({
                    'id': plan[0],
                    'name': plan[1],
                    'description': plan[2]
                })

            events_data.append(event_dict)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'events': events_data,
                'page': page,
                'total_pages': total_pages,
                'unique_names': unique_names,
                'filter_name': filter_name
            })

        return render_template(
            'index.html', 
            events=events_data,
            page=page,
            total_pages=total_pages,
            filter_name=filter_name,
            unique_names=unique_names
        )

    except Exception as e:
        print(f"Ошибка при загрузке данных: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'events': [], 'page': 1, 'total_pages': 1, 'unique_names': [], 'filter_name': ''}), 500
        return render_template('index.html', events=[], page=1, total_pages=1, filter_name='', unique_names=[])

    finally:
        cursor.close()
        conn.close()


@app.route('/delete_security_plan/<int:plan_id>', methods=['POST'])
@jwt_required()
def delete_security_plan(plan_id):
    if 'user_id' not in session:  # Если пользователь не авторизован
        return redirect(url_for('login'))  # Перенаправляем на страницу входа

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM security_plans WHERE id = %s', (plan_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash('План безопасности успешно удален!', 'success')
    return redirect(url_for('security_plans'))



# Роуты для API (для JS)
@app.route('/internal_events', methods=['GET'])
@jwt_required()
def api_internal_events():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM internal_events;')
    events = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(events)

@app.route('/incidents', methods=['GET'])
@jwt_required()
def api_incidents():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents;')
    incidents = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(incidents)

# Логаут пользователя
@app.route('/logout')
@jwt_required()
def logout():
    # Если хочешь поддерживать session, то очищай ее
    session.pop('user_id', None)
    # Но JWT logout лучше делать на клиенте (удалять токен)
    return redirect(url_for('login'))

# Запуск приложения
if __name__ == '__main__':
    app.run(debug=True)
