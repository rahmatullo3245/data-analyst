import streamlit as st
import pandas as pd
import sqlite3
import bcrypt
import plotly.express as px

# Database connection for user login/signup
conn = sqlite3.connect('users.db')  # Connecting to SQLite database
cursor = conn.cursor()

# Create the table if not already present
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
)
''')

# Hashing the password with bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

# Verifying the password
def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash)

# User sign-up function
def sign_up(username, password):
    cursor.execute('''
    SELECT * FROM users WHERE username = ? 
    ''', (username,))
    if cursor.fetchone():
        return False  # User already exists, cannot sign up
    password_hash = hash_password(password)
    cursor.execute('''
    INSERT INTO users (username, password_hash) VALUES (?, ?)
    ''', (username, password_hash))
    conn.commit()
    return True

# User login function
def login(username, password):
    cursor.execute('''
    SELECT password_hash FROM users WHERE username = ?
    ''', (username,))
    result = cursor.fetchone()
    if result and check_password(result[0], password):
        return True
    return False

# Session state for logged-in status
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# Login and Sign-Up form (only shown if user is not logged in)
if not st.session_state.logged_in:
    option = st.radio("Select Action", ["Login", "Sign Up"])

    if option == "Login":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            if login(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                # Do not show success message
                st.rerun()  # This reruns the app and removes the form
            else:
                st.error("Invalid username or password")
    
    elif option == "Sign Up":
        username = st.text_input("New Username")
        password = st.text_input("New Password", type="password")
        
        if st.button("Sign Up"):
            if sign_up(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                # Do not show success message
                st.rerun()  # This reruns the app and removes the form
            else:
                st.error("Username already exists!")

# When the user is logged in, show the main app content
if st.session_state.logged_in:
    st.write(f"Welcome, {st.session_state.username}!")

    if st.button("Log Out"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()  # This reruns the app and removes the form

    # TechShop section
    st.title("TechShop")
    st.markdown("Explore the World of Laptops")
    
    # Add 3 line breaks for extra space
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Reading the CSV file containing laptop data
    df = pd.read_csv('laptop_price.csv', sep=',')
    st.write(f"The available price range is from {df['Price (Euro)'].min()} to {df['Price (Euro)'].max()} Euro.")

    if st.checkbox("Additional Statistics"):
        st.table(df.describe())

    # Add 3 line breaks for extra space
    st.markdown("<br>", unsafe_allow_html=True)

    # Sidebar: Brand selection
    st.sidebar.title("Brands:")
    selected_brand = st.sidebar.selectbox("Select a Brand", df["Company"].unique())

    # Filter the dataframe for selected columns
    d1 = df[['Company', 'CPU_Type', 'RAM (GB)', 'Memory', 'Price (Euro)']]
    filtered_df = d1[d1["Company"] == selected_brand]
    st.dataframe(filtered_df, hide_index=True)

    # Add 3 line breaks for extra space
    st.markdown("<br><br><br>", unsafe_allow_html=True)

    # Sidebar: Price filter with two-way (min and max) range
    st.sidebar.title("Price Range:")
    price_range = st.sidebar.slider(
        "Select Price Range:",
        min_value=df['Price (Euro)'].min(),
        max_value=df['Price (Euro)'].max(),
        value=(df['Price (Euro)'].min(), df['Price (Euro)'].max()),  # Default value (min, max)
        step=1.0,  # Changed step to a float to match min and max types
        format="€%d",  # Display values as Euro
    )

    # Apply filter based on the selected price range
    filtered_df = d1[(d1['Price (Euro)'] >= price_range[0]) & (d1['Price (Euro)'] <= price_range[1])]
    st.dataframe(filtered_df, hide_index=True)

    # Add 3 line breaks for extra space
    st.markdown("<br><br><br>", unsafe_allow_html=True)

    # Bar Chart: Total Prices by Company
    st.subheader("Total Prices by Company")
    grouped_data = df.groupby("Company")["Price (Euro)"].sum().sort_values(ascending=False).reset_index()

    # Bar chart instead of line chart
    fig1 = px.bar(
        grouped_data, 
        x="Company", 
        y="Price (Euro)", 
        labels={"x": "Company", "y": "Total Price (Euro)"}, 
        title="Total Prices by Brand",
        template="plotly_dark",  # Dark background theme
    )
    st.plotly_chart(fig1)

    # Add 3 line breaks for extra space
    st.markdown("<br><br><br>", unsafe_allow_html=True)

    # Box Plot: Price distribution across brands (no animation)
    st.subheader("Price Distribution Across Brands")
    fig2 = px.box(df, x="Company", y="Price (Euro)", title="Price Distribution by Brand", template="plotly_dark")
    st.plotly_chart(fig2)

    # Add 3 line breaks for extra space
    st.markdown("<br><br><br>", unsafe_allow_html=True)

    # Histogram: Price distribution based on RAM
    st.subheader("Price Distribution by RAM Size")
    fig3 = px.histogram(df, x="RAM (GB)", y="Price (Euro)", histfunc="sum", title="Price Distribution by RAM Size", template="plotly_dark")
    st.plotly_chart(fig3)

    # Add 3 line breaks for extra space
    st.markdown("<br><br><br>", unsafe_allow_html=True)

    # Scatter Plot: Relationship between CPU Type and RAM Size (with animation)
    st.subheader("Price Distribution by CPU Type")
    fig4 = px.scatter(df, x="CPU_Type", y="Price (Euro)", color="Company", title="CPU Type vs Price", 
                      template="plotly_dark")  # Added animation here
    st.plotly_chart(fig4)

    # Add 3 line breaks for extra space
    st.markdown("<br><br><br>", unsafe_allow_html=True)

    # Bar Chart: Top 10 most sold brands (no animation)
    st.subheader("Top 10 Most Popular Brands")
    top_brands = df["Company"].value_counts().head(10)
    fig5 = px.bar(top_brands, x=top_brands.index, y=top_brands.values, title="Top 10 Brands by Popularity", template="plotly_dark")
    st.plotly_chart(fig5)

else: 
    st.warning("Please log in or sign up to access the application.")

# Close the database connection
conn.close()
