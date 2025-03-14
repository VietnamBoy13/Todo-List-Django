from celery import shared_task
from django.utils.timezone import now
from django.core.mail import EmailMultiAlternatives
from .models import Notifications, Task
from django.utils.html import strip_tags
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()


@shared_task
def send_welcome_email(user_id):
    try:
        user = User.objects.get(id=user_id)
        subject = 'Добро пожаловать в Todo List'
        message = (
            f'Привет, {user.username},\n\n'
            'Спасибо за регистрацию в Todo List. Теперь вы можете легко создавать и управлять своими задачами.\n\n'
            'Желаем вам хорошего дня!\n\n'
            'С уважением,\nКоманда Todo List'
        )
        email = EmailMultiAlternatives(
            subject=subject,
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.send()
        create_notification(user.id, 'Отправлено приветственное письмо', now())
    except Exception as e:
        create_notification(user_id, f'Ошибка при отправке приветственного письма: {str(e)}', now())


@shared_task
def create_notification(user_id, name, date):
    Notifications.objects.create(
        user_id=user_id,
        name=name,
        date=date,
        notificationsCount=1
    )


@shared_task
def send_email_notifications():
    tasks = Task.objects.filter(
        emailNotification=True,
        notificationTime__isnull=False,
        sent_reminder=False,
        status=Task.PENDING,
        user__email_verified=True,
    )
    for task in tasks:
        due_date = task.dueDate
        notification_time = task.notificationTime
        user = task.user
        fromEmail = settings.DEFAULT_FROM_EMAIL
        receiver_email = user.email
        time_remaining = due_date - timezone.now()
        if time_remaining.total_seconds() <= notification_time * 60:
            task_link = "http://localhost:8000/tasks/running/"
            task_title = task.taskTitle
            task_link_html = f'<a href="{task_link}">{task_title}</a>'
            todo_item_expire = (
                f"Ваша задача '{task_link_html}' истечет через {notification_time} минут!"
            )

            html_content = f"""
                <html>
                <body>
                    <p>{todo_item_expire}</p>
                </body>
                </html>
            """

            text_content = strip_tags(html_content)

            email = EmailMultiAlternatives(
                'Уведомление о задаче',
                text_content,
                fromEmail,
                [receiver_email],
            )
            email.attach_alternative(html_content, "text/html")

            try:
                email.send()
                task.sent_reminder = True
                task.save()

                notifications = Notifications(
                    name=f'Уведомление по задаче "{task.taskTitle}" отправлено',
                    date=timezone.now(),
                    user=user,
                )
                notifications.notificationsCount += 1
                notifications.save()
            except Exception as e:
                notifications = Notifications(
                    name=f'Ошибка при отправке уведомления по задаче "{task.taskTitle}"',
                    date=timezone.now(),
                    user=user,
                )
                notifications.notificationsCount += 1
                notifications.save()
                pass


@shared_task
def update_task_status():
    from Todo_List_App.models import Task
    tasks = Task.objects.filter(status=Task.PENDING)
    for task in tasks:
        if task.dueDate < timezone.now():
            task.status = Task.OVERDUE
            task.save()
