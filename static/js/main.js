document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('echoForm');
    const input = document.getElementById('echoInput');
    const charCount = document.getElementById('charCount');
    const statusMessage = document.getElementById('statusMessage');
    const echoText = document.getElementById('echoText');
    const receivedEcho = document.getElementById('receivedEcho');
    const echoCountSpan = document.getElementById('echoCount');
    const btn = document.getElementById('submitBtn');

    input.addEventListener('input', () => {
        charCount.textContent = `${input.value.length} / 500`;
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const content = input.value.trim();
        if (content.length === 0) return;

        btn.disabled = true;
        statusMessage.textContent = '';
        document.querySelector('.btn-text').style.display = 'none';
        document.querySelector('.btn-loading').style.display = 'inline';

        const response = await fetch('/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content })
        });

        const result = await response.json();

        btn.disabled = false;
        document.querySelector('.btn-text').style.display = 'inline';
        document.querySelector('.btn-loading').style.display = 'none';

        if (result.success) {
            statusMessage.textContent = result.message;
            receivedEcho.style.display = 'block';
            echoText.textContent = result.received_echo;
            echoCountSpan.textContent = result.echo_count;
            input.value = '';
            charCount.textContent = '0 / 500';
        } else {
            statusMessage.textContent = result.error;
        }
    });
});
