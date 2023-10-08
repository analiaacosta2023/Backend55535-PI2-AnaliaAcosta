const socket = io();
const chatBox = document.getElementById('chatBox');
const sendMessageButton = document.getElementById('sendMessageButton');

let user

fetch('/api/sessions/current', {
    method: 'GET',
})
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.status === 'success') {
            user = data.payload;
            socket.emit('authenticated', user);

            sendMessageButton.addEventListener('click', evt => {

                if (chatBox.value.trim().length > 0) {
                    socket.emit('message', { user: user.id, message: chatBox.value })
                    chatBox.value = "";
                }

            })

        } else {
            console.error('Request was not successful');
        }
    })
    .catch(error => {
        console.error('Fetch Error:', error);
        window.location.replace('/login')
    });




socket.on('messageLogs', data => {
    let log = document.getElementById('messageLogs');
    let messages = "";
    data.forEach(message => {

        messages = messages + `${message.user.first_name} dice: ${message.message} </br>`
    })
    log.innerHTML = messages;
})
socket.on('newUserConnected', user => {
    if (!user) return
    Swal.fire({
        toast: true,
        position: "top-right",
        text: "Nuevo usuario conectado",
        title: `${user.first_name} se ha unido al chat`,
        timer: 5000,
        showConfirmButton: false
    })
})

socket.on('error', error => {

    Swal.fire({
        toast: true,
        position: "top-right",
        text: "Error",
        title: `${error}`,
        timer: 5000,
        showConfirmButton: false
    })
})