import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get user's cash balance
    user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]
    cash = user["cash"]

    # Get all stocks where user has shares (summed)
    stocks = db.execute("""
        SELECT symbol, SUM(shares) as shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING shares > 0
    """, session["user_id"])

    # Initialize variables
    grand_total = cash
    stocks_updated = []

    # Get current price for each stock
    for stock in stocks:
        quote = lookup(stock["symbol"])
        stocks_updated.append({
            "symbol": stock["symbol"],
            "name": quote["name"],
            "shares": stock["shares"],
            "price": quote["price"],
            "total": quote["price"] * stock["shares"]
        })
        grand_total += quote["price"] * stock["shares"]

    return render_template("index.html",
                           stocks=stocks_updated,
                           cash=cash,
                           grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol").strip().upper()
        if not symbol:
            return apology("must provide symbol", 400)
        try:
            shares = int(request.form.get("shares"))
            if shares < 1:
                return apology("must provide positive number of shares", 400)
        except ValueError:
            return apology("invalid number of shares", 400)
        stock = lookup(symbol)
        if not stock:
            return apology("invalid stock symbol", 400)
        cost = stock["price"] * shares
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        if cost > user_cash:

            return apology("not enough cash", 400)
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, session["user_id"])
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price)
            VALUES (?, ?, ?, ?)
        """, session["user_id"], symbol, shares, stock["price"])

        # Update user's cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, session["user_id"])

        flash(f"Bought {shares} share(s) of {symbol} for {usd(cost)}!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():

    transactions = db.execute("SELECT * FROM transactions")
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():

    if request.method == "POST":
        # Ensure symbol was submitted
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide stock symbol", 400)

        # Look up stock
        stock = lookup(symbol)
        if not stock:
            return apology("invalid stock symbol", 400)

        # Display stock information
        return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        elif not confirmation or password != confirmation:
            return apology("must provide correct confirmation", 400)
        try:
            db.execute("INSERT INTO users (username,hash) VALUES(?, ?)",
                       username, generate_password_hash(password))
        except:
            return apology("user already exists!", 400)
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Validate symbol
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must select stock", 400)

        # Validate shares
        try:
            shares = int(request.form.get("shares"))
            if shares < 1:
                return apology("must provide positive number of shares", 400)
        except:
            return apology("invalid number of shares", 400)

        # Check user has enough shares
        user_shares = db.execute("""
            SELECT SUM(shares) AS total
            FROM transactions
            WHERE user_id = ? AND symbol = ?
            GROUP BY symbol
        """, session["user_id"], symbol)

        if not user_shares or user_shares[0]["total"] < shares:
            return apology("not enough shares", 400)

        # Get current stock price
        stock = lookup(symbol)
        if not stock:
            return apology("stock lookup failed", 400)

        # Calculate sale value
        sale_value = shares * stock["price"]

        # Record the sale (negative shares)
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price)
            VALUES (?, ?, ?, ?)
        """, session["user_id"], symbol, -shares, stock["price"])

        # Update user's cash (CRITICAL FIX)
        db.execute("""
            UPDATE users
            SET cash = cash + ?
            WHERE id = ?
        """, sale_value, session["user_id"])

        flash(f"Sold {shares} share(s) of {symbol} for {usd(sale_value)}!")
        return redirect("/")

    else:
        # GET request - show stocks user owns
        stocks = db.execute("""
            SELECT symbol
            FROM transactions
            WHERE user_id = ?
            GROUP BY symbol
            HAVING SUM(shares) > 0
        """, session["user_id"])
        return render_template("sell.html", stocks=stocks)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change their password"""

    if request.method == "POST":
        # Get form data
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Validate inputs
        if not current_password or not new_password or not confirmation:
            return apology("must fill all fields", 400)

        if new_password != confirmation:
            return apology("new passwords don't match", 400)

        # Query database for current user
        rows = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        # Ensure current password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], current_password):
            return apology("invalid current password", 403)

        # Update password
        new_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"])

        # Clear session and require re-login
        session.clear()
        flash("Password changed successfully! Please log in again.")
        return redirect("/login")

    else:
        return render_template("change_password.html")
