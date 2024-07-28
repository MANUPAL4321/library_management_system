document.addEventListener('DOMContentLoaded', function() {
    const studentLoginForm = document.getElementById('studentLoginForm');
    const adminLoginForm = document.getElementById('adminLoginForm');

    if (studentLoginForm) {
        studentLoginForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const email = document.getElementById('studentEmail').value;
            const password = document.getElementById('studentPassword').value;
            const errorMessage = document.getElementById('studentErrorMessage');

            // Fetch the actual student password from server (this is just a placeholder)
            fetch('/get_student_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email: email })
            })
            .then(response => response.json())
            .then(data => {
                const correctStudentPassword = data.password;

                if (password !== correctStudentPassword) {
                    errorMessage.textContent = "Your password is wrong. Please enter the correct password.";
                } else {
                    errorMessage.textContent = "";
                    alert('Student login successful!');
                    studentLoginForm.submit();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                errorMessage.textContent = "An error occurred. Please try again.";
            });
        });
    }

    if (adminLoginForm) {
        adminLoginForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const email = document.getElementById('adminEmail').value;
            const password = document.getElementById('adminPassword').value;
            const errorMessage = document.getElementById('adminErrorMessage');

            // Fetch the actual admin password from server (this is just a placeholder)
            fetch('/get_admin_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email: email })
            })
            .then(response => response.json())
            .then(data => {
                const correctAdminPassword = data.password;

                if (password !== correctAdminPassword) {
                    errorMessage.textContent = "Your password is wrong. Please enter the correct password.";
                } else {
                    errorMessage.textContent = "";
                    alert('Admin login successful!');
                    adminLoginForm.submit();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                errorMessage.textContent = "An error occurred. Please try again.";
            });
        });
    }
});
