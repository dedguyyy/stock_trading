# Finance Web Application

This project is a web-based stock trading simulation platform built with Python, Flask, SQLite, and Bootstrap. It allows users to register, log in, get real-time stock quotes, buy and sell stocks, view their portfolio, and track transaction history. The application manages user authentication, secure password storage, and session management.

## Features

- **User Registration & Authentication**
  - Secure registration with password hashing
  - Login and logout functionality
  - Change password feature

- **Portfolio Management**
  - View current holdings with real-time stock prices
  - Display cash balance and total portfolio value

- **Stock Trading**
  - Buy stocks by specifying symbol and number of shares
  - Sell stocks with validation for sufficient shares
  - Real-time stock price lookup

- **Transaction History**
  - View a complete history of all buy and sell transactions

- **User Experience**
  - Flash messages for feedback on actions
  - Input validation and error handling
  - Responsive design using Bootstrap

## Technologies Used

- **Python 3**
- **Flask** (web framework)
- **SQLite** (database)
- **Jinja2** (templating)
- **Bootstrap** (styling)
- **Werkzeug** (password hashing)
- **Flask-Session** (session management)

## File Structure

- `app.py` — Main Flask application with all routes and logic
- `templates/` — HTML templates for all pages (index, login, register, buy, sell, quote, history, etc.)
- `helpers.py` — Helper functions for stock lookup, formatting, and error handling
- `finance.db` — SQLite database storing users and transactions

## How to Run

1. Install dependencies:
    ```sh
    pip install flask flask-session werkzeug
    ```
2. Set up the database schema (users and transactions tables).
3. Run the Flask app:
    ```sh
    flask run
    ```
4. Open your browser and navigate to `http://localhost:5000`

## Example Pages

- **Homepage:** View your portfolio, including stocks owned, current prices, and cash balance.
- **Buy/Sell:** Purchase or sell shares of stocks using real-time prices.
- **Quote:** Look up the latest price for any stock symbol.
- **History:** Review all your past transactions.
- **Change Password:** Securely update your account password.

## Security

- Passwords are securely hashed before storage.
- User sessions are managed securely using server-side sessions.
- Input validation and error handling are implemented throughout.

## License

This project is open source and free to use for educational and
