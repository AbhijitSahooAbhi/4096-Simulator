# To-Do List Application

A full-featured to-do list application built with HTML, CSS, PHP, and JavaScript.

## Features

- ✅ Add new tasks
- ✅ Mark tasks as complete/incomplete
- ✅ Edit existing tasks
- ✅ Delete tasks
- ✅ Filter tasks (All/Active/Completed)
- ✅ Persistent storage using SQLite database
- ✅ Responsive design
- ✅ Real-time updates without page refresh
- ✅ Beautiful gradient UI with smooth animations

## Technology Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: PHP 8.4 with PDO
- **Database**: SQLite
- **API**: RESTful API with JSON responses

## Project Structure

```
todo-list/
├── index.php           # Main application page
├── api/
│   ├── create.php     # Create new task
│   ├── read.php       # Read all tasks (with filtering)
│   ├── update.php     # Update task (text or status)
│   └── delete.php     # Delete task
├── css/
│   └── style.css      # Application styling
├── js/
│   └── app.js         # Frontend logic and AJAX calls
├── db/
│   ├── init.php       # Database initialization
│   └── todos.db       # SQLite database (auto-created)
└── README.md          # This file
```

## Requirements

- PHP 8.0 or higher
- PHP PDO extension
- PHP SQLite extension

## Installation

1. **Install PHP and required extensions** (if not already installed):
   ```bash
   # Amazon Linux 2023
   sudo dnf install -y php php-pdo php-sqlite3
   
   # Ubuntu/Debian
   sudo apt install php php-pdo php-sqlite3
   
   # macOS (using Homebrew)
   brew install php
   ```

2. **Navigate to the project directory**:
   ```bash
   cd /path/to/todo-list
   ```

3. **Start the PHP built-in server**:
   ```bash
   php -S localhost:8000
   ```

4. **Open your browser** and visit:
   ```
   http://localhost:8000
   ```

## Usage

### Adding Tasks
- Type your task in the input field
- Click "Add Task" or press Enter

### Completing Tasks
- Click the circular checkbox next to a task to mark it as complete
- Click again to mark as incomplete

### Editing Tasks
- Click the pencil (✏️) icon to edit a task
- Modify the text and click the save (💾) icon or press Enter

### Deleting Tasks
- Click the trash (🗑️) icon to delete a task
- Confirm the deletion in the popup

### Filtering Tasks
- Click "All" to see all tasks
- Click "Active" to see only incomplete tasks
- Click "Completed" to see only completed tasks

## API Endpoints

### Create Task
```bash
POST /api/create.php
Content-Type: application/json

{
  "task": "Task description"
}
```

### Read Tasks
```bash
GET /api/read.php?filter=all|active|completed
```

### Update Task
```bash
PUT /api/update.php
Content-Type: application/json

# Update task text
{
  "id": 1,
  "task": "Updated task description"
}

# Update completion status
{
  "id": 1,
  "completed": 1
}
```

### Delete Task
```bash
DELETE /api/delete.php
Content-Type: application/json

{
  "id": 1
}
```

## Testing

All API endpoints have been tested and verified:

✅ Create task - Working
✅ Read tasks - Working
✅ Update task text - Working
✅ Update task status - Working
✅ Delete task - Working
✅ Filter tasks - Working
✅ Database persistence - Working

## Database Schema

```sql
CREATE TABLE todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task TEXT NOT NULL,
    completed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

## Security Features

- SQL injection prevention using PDO prepared statements
- XSS protection with HTML escaping
- Input validation on both client and server side
- CORS headers for API security

## Browser Compatibility

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- Mobile browsers

## License

This project is open source and available for personal and commercial use.

## Author

Created with ❤️ using HTML, CSS, PHP, and JavaScript
