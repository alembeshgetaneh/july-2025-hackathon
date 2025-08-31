// queue.js: Dynamic queue updates for real-time UX
function refreshQueue() {
    fetch('/staff/dashboard?ajax=1')
        .then(response => response.json())
        .then(data => {
            // Update queue table, stats, and 'Now Serving' section
            // (You can expand this for admin dashboard as well)
            // Example: document.getElementById('queue-count').innerText = data.total_queue;
            // ...
        });
}
setInterval(refreshQueue, 10000); // Refresh every 10 seconds
// You can add more JS for token display, etc.
