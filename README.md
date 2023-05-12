-------------------------------------------------------------------------
README
-------------------------------------------------------------------------

To run this application, you need to have Python installed on your machine, along with several Python packages. Below, you'll find a list of the necessary packages:

1. Flask: This is a micro web framework written in Python. You can install it using pip:
   pip install flask

2. Flask-SQLAlchemy: This is an extension for Flask that adds support for SQLAlchemy to your application. Install it with pip:
   pip install flask_sqlalchemy

3. Flask-Migrate: This is an extension that handles SQLAlchemy database migrations for Flask applications using Alembic. Install it with pip:
   pip install flask_migrate

4. Flask-Login: This provides user session management for Flask. It handles the common tasks of logging in, logging out, and remembering your users' sessions over extended periods of time. Install it with pip:
   pip install flask_login

5. Requests: This is used for making HTTP requests in Python. Install it with pip:
   pip install requests

6. json: This is used for parsing JSON. It's included in the Python standard library.

7. base64: This is used for encoding and decoding data using the Base64 scheme. It's included in the Python standard library.

To run the application, navigate to the directory containing the Python script and run the following command:

   python <your_script_name>.py

Note: Make sure to replace <your_script_name> with the actual name of your Python script.

Please ensure that you have set up the correct database URI and secret key in the app configuration.

The application will then start and be accessible at http://127.0.0.1:5000
