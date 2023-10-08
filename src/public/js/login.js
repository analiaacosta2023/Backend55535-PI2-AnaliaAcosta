const form = document.getElementById('loginForm');

form.addEventListener('submit', e => {
    e.preventDefault();
    const data = new FormData(form);
    const obj = {};
    data.forEach((value, key) => obj[key] = value);


    fetch('api/sessions/login', {
        method: 'POST',
        body: JSON.stringify(obj),
        headers: {
            'Content-Type': 'application/json'
        }
    }).then(async (result) => {

        if (result.status === 200) {
            const data = await result.json()
            console.log(data)
            window.location.replace('/products')
        } else {
            return await result.json().then(errorData => {
                throw new Error(errorData.error);
            });
        }
    })
        .catch(error => {

            Swal.fire({
                toast: true,
                position: "top-right",
                text: "Error: " + error.message,
                timer: 10000,
                showConfirmButton: false
            });
        })
    form.reset();
})