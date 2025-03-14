from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from Todo_List_App.models import Task, Category, Profile, CustomUser, Notifications, PasswordResetRequest
from Todo_List_App.forms import CustomUserAdminForm

class ProfileInline(admin.StackedInline):
    model = Profile

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'firstName', 'lastName', 'email', 'email_verified', 'is_active', 'is_staff')
    form = CustomUserAdminForm
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Личная информация', {'fields': ('firstName', 'lastName', 'email', 'phone', 'address', 'email_verified')}),
        ('Права доступа', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Важные даты', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2'),
        }),
    )
    inlines = [ProfileInline]
    search_fields = ('username', 'firstName', 'lastName', 'email')
    ordering = ('username',)

class TaskAdmin(admin.ModelAdmin):
    list_display = (
        'taskTitle',
        'category',
        'dueDate',
        'important',
        'user',
        'status',
        'sent_reminder',
        'emailNotification'
    )
    ordering = ('status', 'dueDate',)
    list_filter = [
        'taskTitle',
        'category',
        'dueDate',
        'important',
        'completedDate',
        'createdDate',
        'user',
        'status'
    ]
    fieldsets = (
        (None, {
            'fields': ('taskTitle', 'description', 'category')
        }),
        ('Информация о датах', {
            'fields': ('dueDate', 'createdDate', 'completedDate')
        }),
        ('Статус', {
            'fields': ('important', 'status')
        }),
        ('Информация о пользователе', {
            'fields': ('user',)
        }),
        ('Уведомления', {
            'fields': ('notificationTime', 'sent_reminder', 'emailNotification')
        }),
    )
    search_fields = ('taskTitle', 'description', 'category__name', 'user__username', 'user__email')
    date_hierarchy = 'dueDate'
    list_editable = ('status', 'important')

class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'completedTasksCount', 'enableEmailNotifications', 'gender', 'profilePicture')
    list_filter = ('gender', 'enableEmailNotifications')
    search_fields = ('user__username', 'user__email')

class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'task_count')
    search_fields = ('name', 'user__username', 'user__email')

    def task_count(self, obj):
        return obj.task_count()
    task_count.short_description = 'Количество задач'

class NotificationsAdmin(admin.ModelAdmin):
    list_display = ('date', 'name', 'user', 'unread')
    ordering = ('date',)
    list_filter = ['date', 'user', 'unread']
    search_fields = ('name', 'user__username', 'user__email')

class PasswordResetRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'timestamp', 'reset_link_used', 'reset_link_expiry', 'reset_link_generated_at', 'email_verification_timestamp', 'email_verification_limit')
    fieldsets = (
        (None, {
            'fields': ('user', )
        }),
        ('Сброс пароля', {
            'fields': ('reset_link_used', 'reset_link_expiry', 'reset_link_generated_at', 'email_verification_timestamp', 'email_verification_limit')
        })
    )
    ordering = ('timestamp',)
    list_filter = ('timestamp', 'user__username', 'user__email')
    search_fields = ('user__username', 'user__email')

admin.site.register(PasswordResetRequest, PasswordResetRequestAdmin)
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Profile, ProfileAdmin)
admin.site.register(Notifications, NotificationsAdmin)
admin.site.register(Category, CategoryAdmin)
admin.site.register(Task, TaskAdmin)
