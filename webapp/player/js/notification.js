// This is a very basic notification system
// We should definitely move away from plain JavaScript and use a library instead
export function showNotification(message, type) {
  const notification = document.getElementById('notification');
  notification.style.display = 'flex';
  const messageElement = document.getElementById('notification-message');
  messageElement.innerText = message;

  notification.className = `notification-${type}`; // Example: notification-success, notification-error

  notification.style.display = 'flex';

  const closeButton = document.getElementById('notification-close');
  closeButton.onclick = () => {
    notification.style.display = 'none';
  };

  setTimeout(() => {
    notification.style.display = 'none';
  }, 60_000);
}
