document.addEventListener('DOMContentLoaded', function() {
    const todoForm = document.getElementById('todo-form');
    const todoInput = document.getElementById('todo-input');
    const todoList = document.getElementById('todo-list');

    // Load todos from server
    loadTodos();

    todoForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const todoText = todoInput.value.trim();
        if (todoText !== '') {
            addTodoToServer(todoText);
            todoInput.value = '';
        }
    });

    function addTodo(text, completed = false, index = null) {
        const li = document.createElement('li');
        li.innerHTML = `
            <span class="${completed ? 'completed' : ''}">${text}</span>
            <button class="delete-btn">Delete</button>
        `;

        const deleteBtn = li.querySelector('.delete-btn');
        deleteBtn.addEventListener('click', function() {
            const liIndex = Array.from(todoList.children).indexOf(li);
            deleteTodoFromServer(liIndex);
        });

        const span = li.querySelector('span');
        span.addEventListener('click', function() {
            const liIndex = Array.from(todoList.children).indexOf(li);
            const isCompleted = span.classList.contains('completed');
            updateTodoOnServer(liIndex, !isCompleted);
        });

        todoList.appendChild(li);
    }

    function addTodoToServer(text) {
        fetch('add_todo.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ todo: text }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadTodos();
            } else {
                alert('Error adding todo: ' + data.error);
            }
        })
        .catch(error => console.error('Error:', error));
    }

    function updateTodoOnServer(index, completed) {
        fetch('update_todo.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ index, completed }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadTodos();
            } else {
                alert('Error updating todo: ' + data.error);
            }
        })
        .catch(error => console.error('Error:', error));
    }

    function deleteTodoFromServer(index) {
        fetch('delete_todo.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ index }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadTodos();
            } else {
                alert('Error deleting todo: ' + data.error);
            }
        })
        .catch(error => console.error('Error:', error));
    }

    function loadTodos() {
        fetch('get_todos.php')
        .then(response => response.json())
        .then(todos => {
            todoList.innerHTML = '';
            todos.forEach(todo => {
                addTodo(todo.text, todo.completed);
            });
        })
        .catch(error => console.error('Error:', error));
    }
});