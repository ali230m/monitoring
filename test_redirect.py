# test_redirect.py
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/')
def home():
    return 'Home Page'

@app.route('/redirect')
def redir():
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
