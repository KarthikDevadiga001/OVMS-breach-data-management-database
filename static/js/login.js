document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        })
    });

    const data = await response.json();
    if (data.success) {
        window.location.href = data.role === 'admin' ? '/admin/dashboard' : '/professional/dashboard';
    }
});

