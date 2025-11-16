// API Base URL
const API_BASE = 'api/';

// DOM Elements
const todoInput = document.getElementById('todoInput');
const addBtn = document.getElementById('addBtn');
const todoList = document.getElementById('todoList');
const emptyState = document.getElementById('emptyState');
const filterBtns = document.querySelectorAll('.filter-btn');
const taskCount = document.getElementById('taskCount');

// Current filter
let currentFilter = 'all';

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    loadTodos();
    setupEventListeners();
});

// Setup event listeners
function setupEventListeners() {
    addBtn.addEventListener('click', addTodo);
    todoInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            addTodo();
        }
    });

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.filter;
            loadTodos();
        });
    });
}

// Load todos from API
async function loadTodos() {
    try {
        const response = await fetch(`${API_BASE}read.php?filter=${currentFilter}`);
        const data = await response.json();

        if (data.success) {
            renderTodos(data.todos);
            updateTaskCount(data.todos.length);
        } else {
            console.error('Error loading todos:', data.error);
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

// Render todos to DOM
function renderTodos(todos) {
    todoList.innerHTML = '';

    if (todos.length === 0) {
        emptyState.classList.add('show');
        todoList.style.display = 'none';
    } else {
        emptyState.classList.remove('show');
        todoList.style.display = 'block';

        todos.forEach(todo => {
            const li = createTodoElement(todo);
            todoList.appendChild(li);
        });
    }
}

// Create todo element
function createTodoElement(todo) {
    const li = document.createElement('li');
    li.className = `todo-item ${todo.completed == 1 ? 'completed' : ''}`;
    li.dataset.id = todo.id;

    li.innerHTML = `
        <div class="checkbox ${todo.completed == 1 ? 'checked' : ''}" onclick="toggleTodo(${todo.id}, ${todo.completed})"></div>
        <span class="todo-text">${escapeHtml(todo.task)}</span>
        <input type="text" class="edit-input" value="${escapeHtml(todo.task)}">
        <div class="todo-actions">
            <button class="action-btn edit-btn" onclick="editTodo(${todo.id})" title="Edit">✏️</button>
            <button class="action-btn delete-btn" onclick="deleteTodo(${todo.id})" title="Delete">🗑️</button>
        </div>
    `;

    return li;
}

// Add new todo
async function addTodo() {
    const task = todoInput.value.trim();

    if (!task) {
        alert('Please enter a task!');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}create.php`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ task })
        });

        const data = await response.json();

        if (data.success) {
            todoInput.value = '';
            loadTodos();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to add task');
    }
}

// Toggle todo completion
async function toggleTodo(id, currentStatus) {
    const newStatus = currentStatus == 1 ? 0 : 1;

    try {
        const response = await fetch(`${API_BASE}update.php`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id, completed: newStatus })
        });

        const data = await response.json();

        if (data.success) {
            loadTodos();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to update task');
    }
}

// Edit todo
function editTodo(id) {
    const todoItem = document.querySelector(`[data-id="${id}"]`);
    const todoText = todoItem.querySelector('.todo-text');
    const editInput = todoItem.querySelector('.edit-input');
    const editBtn = todoItem.querySelector('.edit-btn');

    if (editInput.classList.contains('active')) {
        // Save changes
        const newTask = editInput.value.trim();
        if (newTask) {
            updateTodoText(id, newTask);
        }
        editInput.classList.remove('active');
        todoText.classList.remove('editing');
        editBtn.textContent = '✏️';
    } else {
        // Enter edit mode
        editInput.classList.add('active');
        todoText.classList.add('editing');
        editInput.focus();
        editBtn.textContent = '💾';

        // Save on Enter key
        editInput.onkeypress = (e) => {
            if (e.key === 'Enter') {
                editBtn.click();
            }
        };
    }
}

// Update todo text
async function updateTodoText(id, task) {
    try {
        const response = await fetch(`${API_BASE}update.php`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id, task })
        });

        const data = await response.json();

        if (data.success) {
            loadTodos();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to update task');
    }
}

// Delete todo
async function deleteTodo(id) {
    if (!confirm('Are you sure you want to delete this task?')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}delete.php`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id })
        });

        const data = await response.json();

        if (data.success) {
            loadTodos();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to delete task');
    }
}

// Update task count
function updateTaskCount(count) {
    taskCount.textContent = `${count} ${count === 1 ? 'task' : 'tasks'}`;
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
