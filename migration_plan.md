# Supabase Migration Plan

## Overview
Replace all MySQL database connections with Supabase client calls throughout the Flask helpdesk application.

## Files to Update

### High Priority (Core Application)
1. **app.py** - 15+ MySQL connection instances
2. **routes/api.py** - 5+ API endpoints
3. **sla_helper.py** - SLA calculation functions
4. **sla_breach_helper.py** - SLA breach detection

### Migration Patterns

#### Pattern 1: Simple SELECT queries
```python
# Before
conn = get_db_connection()
cursor = conn.cursor(dictionary=True)
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
user = cursor.fetchone()
cursor.close()
conn.close()

# After
response = supabase.table("users").select("*").eq("email", email).execute()
user = response.data[0] if response.data else None
```

#### Pattern 2: INSERT operations
```python
# Before
conn = get_db_connection()
cursor = conn.cursor()
cursor.execute("INSERT INTO users (...) VALUES (...)", (values,))
conn.commit()
cursor.close()
conn.close()

# After
response = supabase.table("users").insert(data_dict).execute()
```

#### Pattern 3: UPDATE operations
```python
# Before
conn = get_db_connection()
cursor = conn.cursor()
cursor.execute("UPDATE users SET ... WHERE id = %s", (values,))
conn.commit()
cursor.close()
conn.close()

# After
response = supabase.table("users").update(update_dict).eq("id", user_id).execute()
```

#### Pattern 4: Complex queries with JOINs
```python
# Before
cursor.execute("""
    SELECT t.*, u.name as user_name 
    FROM tickets t 
    JOIN users u ON t.user_id = u.id 
    WHERE t.id = %s
""", (ticket_id,))

# After
response = supabase.table("tickets").select("*, users(name)").eq("id", ticket_id).execute()
```

## Step-by-Step Implementation

### Step 1: Update app.py
- [ ] Replace verify_email route
- [ ] Replace login route database calls
- [ ] Replace admin_dashboard route
- [ ] Replace user_dashboard route
- [ ] Replace agent_dashboard route
- [ ] Replace ticket_detail route
- [ ] Replace submit_ticket route
- [ ] Replace edit_ticket route

### Step 2: Update API routes
- [ ] Replace get_ticket_comments endpoint
- [ ] Replace add_ticket_comment endpoint
- [ ] Replace update_comment endpoint
- [ ] Replace delete_comment endpoint
- [ ] Replace get_sla_status endpoint

### Step 3: Update helper functions
- [ ] Update sla_helper.py functions
- [ ] Update sla_breach_helper.py functions

### Step 4: Cleanup
- [ ] Remove get_db_connection() function
- [ ] Remove MySQL from requirements.txt
- [ ] Update environment variables documentation
- [ ] Test all functionality

## Testing Checklist
- [ ] User registration and login
- [ ] Ticket creation and management
- [ ] Admin dashboard functionality
- [ ] Agent dashboard functionality
- [ ] SLA calculations
- [ ] Comment system
- [ ] Email verification
- [ ] Password reset functionality
