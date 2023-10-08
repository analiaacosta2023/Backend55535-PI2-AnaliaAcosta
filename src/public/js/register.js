const form = document.getElementById('registerForm');

form.addEventListener('submit', e => {
    e.preventDefault();
    const data = new FormData(form);
    const obj = {};
    data.forEach((value, key) => obj[key] = value);
    fetch('api/sessions/register', {
        method: 'POST',
        body: JSON.stringify(obj),
        headers: {
            'Content-Type': 'application/json'
        }
    }).then(result => {
        if (result.status === 200) {

            Swal.fire(
                {
                    toast: true,
                    position: "top-right",
                    text: "Te registraste con éxito!",
                }).then(
                    setTimeout(window.location.replace('/login'), 10000)    
                )
        } else {
            return result.json().then(errorData => {
                throw new Error(errorData.error);
            });
        }
    }).catch(error => {

        Swal.fire({
            toast: true,
            position: "top-right",
            text: "Error: " + error.message,
            timer: 10000,
            showConfirmButton: false
        });
    })
})