import os
from flask import Flask, jsonify, request, Response, send_file, session
from flask_cors import CORS
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv
from datetime import datetime, timedelta
from urllib.parse import urlparse
import csv
from io import StringIO,BytesIO

import logging

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Enable CORS to allow requests from React app
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', 'memcached', etc.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Set this in your .env file
app.config['SESSION_COOKIE_NAME'] = 'my_session_cookie'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Adjust as needed
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Set session lifetime\

print(f"POSTGRES_URL: {os.getenv('POSTGRES_URL')}")

# Database connection function
def db_connection():
    database_url = os.getenv("POSTGRES_URL")
    parsed_url = urlparse(database_url)
    conn = psycopg2.connect(
        host=parsed_url.hostname,
        port=parsed_url.port,
        database=parsed_url.path[1:],
        user=parsed_url.username,
        password=parsed_url.password,
        sslmode='require'
    )
    return conn

@app.route('/test', methods=['GET'])
def test_db():
    try:
        conn = db_connection()
        return jsonify({"message": "Database connection successful!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# Function to create tables if they don't exist
def create_tables():
    conn = db_connection()
    if conn:
        cur = conn.cursor()
        try:
            # Create companies table
            create_companies_table_query = '''
            CREATE TABLE IF NOT EXISTS companies (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL
            );
            '''
            cur.execute(create_companies_table_query)
            print("Companies table created successfully")

            # Create users table with company_id and role
            create_users_table_query = '''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role VARCHAR(50) CHECK (role IN ('admin', 'user')) NOT NULL,
                company_id INT,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE SET NULL
            );
            '''
            cur.execute(create_users_table_query)
            print("Users table created successfully")
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]

# Insert default admin if no users exist
            if user_count == 0:
                insert_admin_query = '''
                INSERT INTO users (username, password, role) VALUES (%s, %s, %s)
                '''
                cur.execute(insert_admin_query, ('admin', '1234', 'admin'))
                print("Default admin user created successfully")

            # Create vendors table
            create_vendors_table_query = '''
            CREATE TABLE IF NOT EXISTS vendors (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                company_id INT,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            );
            '''
            cur.execute(create_vendors_table_query)
            print("Vendors table created successfully")

            # Create customers table with checkboxes and company_id
            create_customers_table_query = '''
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                phone VARCHAR(20),
                product_name VARCHAR(100),
                serialnumber VARCHAR(100),
                problem TEXT,
                received_date DATE,
                delivered_date DATE,
                estimate TEXT,
                vendor_id INT,
                company_id INT,
                checkbox1 BOOLEAN DEFAULT FALSE,
                checkbox2 BOOLEAN DEFAULT FALSE,
                checkbox3 BOOLEAN DEFAULT FALSE,
                checkbox4 BOOLEAN DEFAULT FALSE,
                checkbox5 BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE SET NULL,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            );
            '''
            cur.execute(create_customers_table_query)
            print("Customers table created successfully")

            conn.commit()

        except Exception as e:
            print(f"Error during table creation: {e}")
        finally:
            cur.close()
            conn.close()
    else:
        print("Error connecting to the database.")

# Create tables when the application starts
create_tables()

# Route to add customer details
@app.route('/api/add-customer', methods=['POST'])
def add_customer():
    print("Received POST request to add customer")
    customer_data = request.get_json()
    
    # Accessing checkboxes directly from the 'checkboxes' dictionary
    checkboxes = customer_data.get('checkboxes', {})
    
    checkbox1 = checkboxes.get('checkbox1', False)
    checkbox2 = checkboxes.get('checkbox2', False)
    checkbox3 = checkboxes.get('checkbox3', False)
    checkbox4 = checkboxes.get('checkbox4', False)
    checkbox5 = checkboxes.get('checkbox5', False)
    
    print(f"Checkbox values: checkbox1={checkbox1}, checkbox2={checkbox2}, checkbox3={checkbox3}, checkbox4={checkbox4}, checkbox5={checkbox5}")

    # Get company_id from headers
    company_id = request.headers.get('company')  # Ensure the header name matches what you send from the frontend

    conn = db_connection()
    if conn:
        cur = conn.cursor()
        
        query = sql.SQL("""
            INSERT INTO customers (
                name, email, phone, product_name, serialnumber, problem, 
                received_date, checkbox1, checkbox2, checkbox3, checkbox4, checkbox5, company_id
            ) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """)
        
        values = (
            customer_data['name'],
            customer_data['email'],
            customer_data['phone'],
            customer_data['product_name'],
            customer_data['serialnumber'],
            customer_data['problem'],
            customer_data['received_date'],
            checkbox1,
            checkbox2,
            checkbox3,
            checkbox4,
            checkbox5,
            company_id  # Include company_id in the values
        )
        
        print(f"Values to be inserted: {values}")  # Log the final values being inserted
        
        try:
            cur.execute(query, values)
            conn.commit()
            return jsonify({"message": "Customer added successfully!"}), 201
        except Exception as e:
            print(f"Error inserting customer: {e}")
            return jsonify({"message": "Error inserting customer"}), 500
        finally:
            cur.close()
            conn.close()
    return jsonify({"message": "Error connecting to the database"}), 500

# Route to fetch all customers
@app.route('/api/customers', methods=['GET'])
def get_customers():
    company_id = request.headers.get('company')  # Get company_id from headers
    role = request.headers.get('role')  # Get user role from headers

    if not role:
        return jsonify({"message": "Unauthorized access"}), 401

    conn = db_connection()
    if conn:
        cur = conn.cursor()
        if role == 'admin':
            # Admin can access all customers
            cur.execute("SELECT * FROM customers")
        else:
            # Regular user can only access customers associated with their company_id
            cur.execute("SELECT * FROM customers WHERE company_id = %s", (company_id,))

        customers = cur.fetchall()
        
        column_names = [desc[0] for desc in cur.description]
        customers_list = [dict(zip(column_names, customer)) for customer in customers]

        cur.close()
        conn.close()

        return jsonify(customers_list)

    return jsonify({"message": "Error connecting to the database"}), 500

# Route to add vendor details
@app.route('/api/add-vendor', methods=['POST'])
def add_vendor():
    vendor_data = request.get_json()
    conn = db_connection()
    if conn:
        cur = conn.cursor()
        query = sql.SQL("INSERT INTO vendors (name) VALUES (%s)")
        cur.execute(query, (vendor_data['name'],))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Vendor added successfully!"}), 201
    return jsonify({"message": "Error connecting to the database"}), 500

# Route to fetch all vendors
@app.route('/api/vendors', methods=['GET'])
def get_vendors():
    conn = db_connection()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM vendors")
        vendors = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(vendors)
    return jsonify({"message": "Error connecting to the database"}), 500

# Route to assign customer to vendor
@app.route('/api/vendors/assign_customer', methods=['POST'])
def assign_customer_to_vendor():
    data = request.json
    customer_id = data.get("customer_id")
    vendor_id = data.get("vendor_id")
    old_vendor_id = data.get("old_vendor_id")
    old_vendor_estimate = data.get("old_vendor_estimate")
    
    if not customer_id or not vendor_id:
        return jsonify({"message": "Customer ID and Vendor ID are required"}), 400

    conn = db_connection()
    if conn:
        cur = conn.cursor()
        try:
            assigned_date = datetime.now().strftime('%Y-%m-%d')  # Get today's date

            # Update the customer record with the vendor_id and assigned_date
            cur.execute("""
                UPDATE customers 
                SET vendor_id = %s, assigned_date = %s, 
                    history = COALESCE(history, '[]')::jsonb || jsonb_build_array(jsonb_build_object('vendor_id', %s, 'vendor_estimate', %s))
                WHERE id = %s
            """, (vendor_id, assigned_date, old_vendor_id, old_vendor_estimate, customer_id))
            
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"message": "Customer assigned successfully", "assigned_date": assigned_date}), 200
        except psycopg2.Error as e:
            conn.rollback()
            cur.close()
            conn.close()
            return jsonify({"message": "Error assigning customer", "error": str(e)}), 500
    return jsonify({"message": "Error connecting to the database"}), 500

# Route to get a customer's details by their ID
@app.route('/api/customers/<int:id>', methods=['GET'])
def get_customer_by_id(id):
    conn = db_connection()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM customers WHERE id = %s", (id,))
        customer = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(customer) if customer else jsonify({"message": "Customer not found"}), 404
    return jsonify({"message": "Error connecting to the database"}), 500

# Route to update estimate for a customer
@app.route('/api/customers/<int:id>/estimate', methods=['PUT'])
def update_estimate(id):
    estimate_data = request.get_json()
    conn = db_connection()
    if conn:
        cur = conn.cursor()
        query = sql.SQL("UPDATE customers SET estimate = %s WHERE id = %s")
        cur.execute(query, (estimate_data['estimate'], id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Estimate updated successfully!"}), 200
    return jsonify({"message": "Error connecting to the database"}), 500

# Route to generate PDF (this could be implemented via a PDF library like ReportLab)
@app.route('/api/generate_invoice/<int:id>', methods=['GET'])
def generate_invoice(id):
    return jsonify({"message": "Invoice PDF generated for customer ID: " + str(id)})

@app.route('/api/update-delivered-date/<int:customer_id>', methods=['PUT'])
def update_delivered_date(customer_id):
    delivered_date = datetime.now().strftime('%Y-%m-%d')
    conn = db_connection()
    if conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE customers SET delivered_date = %s WHERE id = %s", (delivered_date, customer_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Delivered date updated successfully", "delivered_date": delivered_date})

    return jsonify({"error": "Error updating delivered date"}), 500

@app.route('/api/add-estimate', methods=['POST'])
def add_estimate():
    estimate_data = request.get_json()
    customer_id = estimate_data.get('customer_id')
    estimate = estimate_data.get('estimate')

    if not customer_id or estimate is None:
        return jsonify({"message": "Please provide both customer_id and estimate."}), 400

    conn = db_connection()
    if conn:
        cur = conn.cursor()
        query = "UPDATE customers SET estimate = %s WHERE id = %s"
        try:
            cur.execute(query, (estimate, customer_id))
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"message": "Estimate added successfully!"}), 201
        except psycopg2.Error as e:
            conn.rollback()
            return jsonify({"message": "Error adding estimate", "error": str(e)}), 500

    return jsonify({"message": "Error connecting to the database"}), 500

@app.route('/api/vendors/<int:vendor_id>', methods=['GET'])
def get_vendor_details(vendor_id):
    conn = db_connection()
    
    if conn:
        cur = conn.cursor()
        query = "SELECT * FROM vendors WHERE id = %s"
        
        try:
            cur.execute(query, (vendor_id,))
            vendor = cur.fetchone()
            
            if vendor:
                vendor_data = {
                    "vendor_id": vendor[0],
                    "name": vendor[1]
                }
                conn.close()
                return jsonify(vendor_data), 200
            else:
                conn.close()
                return jsonify({"message": "Vendor not found"}), 404
        except psycopg2.Error as e:
            conn.rollback()
            conn.close()
            return jsonify({"message": "Error fetching vendor details", "error": str(e)}), 500

    return jsonify({"message": "Error connecting to the database"}), 500

# Route to delete a vendor by their ID
@app.route('/api/vendors/<int:id>', methods=['DELETE'])
def delete_vendor(id):
    conn = db_connection()
    if conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM vendors WHERE id = %s", (id,))
            vendor = cur.fetchone()
            
            if vendor:
                cur.execute("DELETE FROM vendors WHERE id = %s", (id,))
                conn.commit()
                cur.close()
                conn.close()
                return jsonify({"message": f"Vendor with ID {id} deleted successfully!"}), 200
            else:
                return jsonify({"message": f"Vendor with ID {id} not found"}), 404
        except psycopg2.Error as e:
            conn.rollback()
            return jsonify({"message": "Error deleting vendor", "error": str(e)}), 500
    return jsonify({"message": "Error connecting to the database"}), 500

@app.route('/api/vendors/<int:vendor_id>/customers', methods=['GET'])
def list_assigned_customers(vendor_id):
    company_id = request.headers.get('company')  # Get company_id from headers
    role = request.headers.get('role')  # Get user role from headers

    if not role:
        return jsonify({"message": "Unauthorized access"}), 401

    conn = db_connection()
    if conn:
        cur = conn.cursor()
        try:
            # Check if the user is an admin
            if role == 'admin':
                # Admin can see all customers assigned to the vendor
                cur.execute("SELECT * FROM customers WHERE vendor_id = %s", (vendor_id,))
            else:
                # Regular user can only see customers associated with their company_id
                cur.execute("SELECT * FROM customers WHERE vendor_id = %s AND company_id = %s", (vendor_id, company_id))

            customers = cur.fetchall()

            # Get column names
            column_names = [desc[0] for desc in cur.description]
            customers_list = [dict(zip(column_names, customer)) for customer in customers]

            cur.close()
            conn.close()
            return jsonify(customers_list), 200
        except psycopg2.Error as e:
            conn.rollback()
            cur.close()
            conn.close()
            return jsonify({"message": "Error fetching assigned customers", "error": str(e)}), 500
    return jsonify({"message": "Error connecting to the database"}), 500

@app.route('/api/customers/<int:id>/update_received_date', methods=['POST'])
def update_received_date(id):
    data = request.get_json()
    received_date = data.get("received_date")
    remark = data.get("remark")
    checkbox6 = data.get("checkbox6")
    vendor_estimate = data.get("vendor_estimate")

    if not received_date:
        return jsonify({"message": "Received date is required"}), 400

    conn = db_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE customers 
                SET received_vendor_date = %s, remark = %s, checkbox6 = %s, vendor_estimate = %s 
                WHERE id = %s RETURNING *
                """,
                (received_date, remark, checkbox6, vendor_estimate, id)
            )
            updated_customer = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()

            if updated_customer:
                return jsonify({"message": "Received date updated successfully", "customer": updated_customer}), 200
            else:
                return jsonify({"message": "Customer not found"}), 404
        except Exception as e:
            return jsonify({"message": "Database error", "error": str(e)}), 500

    return jsonify({"message": "Error connecting to the database"}), 500

@app.route('/api/export-customers', methods=['GET'])
def export_customers():
    conn = db_connection()
    if conn:
        cur = conn.cursor()
        try:
            query = """
                SELECT id, name, email, phone, product_name, serialnumber, problem, 
                       received_date, delivered_date, estimate, checkbox1, checkbox2, 
                       checkbox3, checkbox4, checkbox5 
                FROM customers
            """
            print("Executing Query:", query)
            cur.execute(query)
            customers = cur.fetchall()
            print("Fetched Customers:", customers)

            if not customers:
                return jsonify({"message": "No customer data found"}), 404

            output = StringIO()
            writer = csv.writer(output)

            writer.writerow([
                'ID', 'Name', 'Email', 'Phone', 'Product Name', 'Serial Number', 'Problem',
                'Received Date', 'Delivered Date', 'Estimate', 'Checkbox 1', 'Checkbox 2',
                'Checkbox 3', 'Checkbox 4', 'Checkbox 5'
            ])

            for customer in customers:
                customer = tuple(
                    str(value) if isinstance(value, (datetime.date, datetime.strptime)) else value
                    for value in customer
                )
                writer.writerow(customer)

            cur.close()
            conn.close()

            return Response(output.getvalue(), mimetype="text/csv",
                            headers={"Content-Disposition": "attachment; filename=customers.csv"})

        except Exception as e:
            print("❌ Error:", str(e))
            cur.close()
            conn.close()
            return jsonify({"message": "Error exporting customers", "error": str(e)}), 500

    return jsonify({"message": "Error connecting to the database"}), 500

@app.route('/api/update-customers/<int:id>/update_received_date', methods=['PUT'])
def update_customer(id):
    data = request.get_json()
    conn = db_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE customers SET name = %s, email = %s, phone = %s, product_name = %s, serialnumber = %s, problem = %s, received_vendor_date = %s WHERE id = %s RETURNING *",
                (data.get("name"), data.get("email"), data.get("phone"), data.get("product_name"), data.get("serialnumber"), data.get("problem"), data.get("received_date"), id)
            )
            updated_customer = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()

            if updated_customer:
                return jsonify({"message": "Customer updated successfully", "customer": updated_customer}), 200
            else:
                return jsonify({"message": "Customer not found"}), 404
        except Exception as e:
            return jsonify({"message": "Database error", "error": str(e)}), 500

    return jsonify({"message": "Error connecting to the database"}), 500

@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    try:
        conn = db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, company_id, role FROM users WHERE username = %s;", (username,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404

        user_id, stored_password, company_id, role = user

        if password == stored_password:
            session['username'] = username  # Store username in the session
            session['company_id'] = company_id  # Store company_id in the session
            session['role'] = role  # Store role in the session
            session.permanent = True  # Make the session permanent
            cursor.close()
            conn.close()
            return jsonify({
                "message": "Login successful", 
                "username": username,
                "company_id": company_id,
                "role": role
            }), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({"error": "Invalid credentials"}), 400

    except Exception as e:
        logging.error(f"Error during login: {str(e)}")
        return jsonify({"error": "An internal error occurred, please try again later"}), 500

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')  # New field for user type
    company_id = data.get('company_id')  # New field for company ID

    if not username or not password or not role :
        return jsonify({"error": "Username, password, user type, and company are required"}), 400

    try:
        conn = db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({"error": "Username already exists"}), 400

        cursor.execute(
            "INSERT INTO users (username, password, role, company_id) VALUES (%s, %s, %s, %s) RETURNING id;",
            (username, password, role, company_id)
        )
        user_id = cursor.fetchone()[0]
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({"message": "User  registered successfully", "user_id": user_id}), 201

    except Exception as e:
        print(f"Error during registration: {str(e)}")  # Log the error

        return jsonify({"error": str(e)}), 500

# Logout user route
@app.route('/api/logout', methods=['POST'])
def logout_user():
    session.pop('username', None)  # Remove username from the session
    return jsonify({"message": "Logged out successfully"}), 200

# Check session route for debugging
@app.route('/api/check_session', methods=['GET'])
def check_session():
    if 'username' in session:
        return jsonify({'logged_in': True, 'username': session['username']}), 200
    else:
        return jsonify({'message': 'Unauthorized access. Please log in.'}), 401
    
    
    
@app.route('/api/vendors/<int:id>/update-total', methods=['PUT'])
def update_vendor_total(id):
    data = request.get_json()  # Get the data from the request body
    new_total = data.get("total")

    if  new_total is None:
        return jsonify({"message": "Total value is required"}), 400

    conn = db_connection()
    
    if conn:
        try:
            cur = conn.cursor()
            # Use SQL placeholders to prevent SQL injection
            cur.execute(
                """
                UPDATE vendors 
                SET total = %s 
                WHERE id = %s 
                RETURNING id, total;
                """, 
                (new_total, id)
            )
            updated_vendor = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()

            if updated_vendor:
                return jsonify({"message": "Vendor total updated successfully", "vendor": updated_vendor}), 200
            else:
                return jsonify({"message": "Vendor not found"}), 404

        except Exception as e:
            return jsonify({"message": "Database error", "error": str(e)}), 500

    return jsonify({"message": "Error connecting to the database"}), 500




@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        conn = db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, username, password, company_id, role FROM users;")  # Adjust the query based on your database schema
        users = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify([{"id": user[0], "username": user[1], "password": user[2], "company_id": user[3],"role": user[4]} for user in users]), 200

    except Exception as e:
        print(f"Error fetching users: {str(e)}")  # Log the error
        return jsonify({"error": str(e)}), 500

# Route to fetch all companies
@app.route('/api/companies', methods=['GET'])
def get_companies():
    try:
        conn = db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, name FROM companies;")  # Adjust the query based on your database schema
        companies = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify([{"id": company[0], "name": company[1]} for company in companies]), 200

    except Exception as e:
        print(f"Error fetching companies: {str(e)}")  # Log the error
        return jsonify({"error": str(e)}), 500

# Route to update a user
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        data = request.json
        username = data.get('name')
        password = data.get('password')
        company_id = data.get('company_id')
        role = data.get('role')

        conn = db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET username = %s, password = %s, company_id = %s,role =%s WHERE id = %s",
            (username, password, company_id,role, user_id)
        )
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({"message": "User  updated successfully"}), 200

    except Exception as e:
        print(f"Error updating user: {str(e)}")  # Log the error
        return jsonify({"error": str(e)}), 500
 
 
 
 
@app.route('/api/upload-company', methods=['POST'])
def upload_company():
    data = request.form
    logo = request.files.get('logo')

    if not logo:
        return jsonify({"message": "No logo file provided"}), 400

    company_name = data.get("companyName")
    if not company_name:
        return jsonify({"message": "Company name is required"}), 400

    try:
        # Read the logo file as binary
        logo_data = logo.read()

        # Insert into the database
        conn = db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO companies (name, logo) VALUES (%s, %s)', (company_name, logo_data))
            conn.commit()
            cursor.close()
            conn.close()

        return jsonify({"message": "Company uploaded successfully"}), 201
    except Exception as e:
        return jsonify({"message": "Database error", "error": str(e)}), 500
    


@app.route('/api/company/<int:company_id>', methods=['GET'])
def fetch_logo(company_id):
    logging.debug(f"Fetching logo for company ID: {company_id}")
    try:
        conn = db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute('SELECT logo FROM companies WHERE id = %s', (company_id,))
            logo_data = cursor.fetchone()

            if logo_data is None:
                logging.warning(f"No logo found for company ID: {company_id}")
                return jsonify({"message": "Logo not found"}), 404

            # Convert binary data to BytesIO for sending as a file
            logo_stream = BytesIO(logo_data[0])
            cursor.close()
            conn.close()

            return send_file(logo_stream, mimetype='image/png')  # Adjust mimetype as necessary
        else:
            logging.error("Database connection failed")
            return jsonify({"message": "Database connection failed"}), 500
    except Exception as e:
        logging.error(f"Error fetching logo: {e}")
        return jsonify({"message": "Database error", "error": str(e)}), 500
    
if __name__ == '__main__':
    app.run(debug=True)
