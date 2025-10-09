import { TranslatedString, t } from './i18n';

type NotificationType = 'success' | 'error';

export function showNotification(message: TranslatedString, type: NotificationType) {
  const notification = document.getElementById('notification');
  if (!notification) return;

  const messageElement = document.getElementById('notification-message');
  if (!messageElement) return;

  const closeButton = document.getElementById('notification-close');
  if (!closeButton) return;

  messageElement.textContent = message;
  closeButton.textContent = t('ui.close');
  notification.className = type === 'error' ? 'notification-error' : 'notification-success';
  notification.style.display = 'flex';

  closeButton.onclick = () => {
    notification.style.display = 'none';
  };

  setTimeout(() => {
    notification.style.display = 'none';
  }, 60000);
}
