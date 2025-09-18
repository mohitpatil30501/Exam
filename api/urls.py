from django.urls import path

from . import views

urlpatterns = [
    path('accounts/login', views.Users.login),
    path('accounts/register', views.Users.register),
    path('accounts/logout', views.Users.logout),
    path('accounts/forgot_password', views.Users.forgot_password),
    path('accounts/reset_password', views.Users.reset_password),
    path('accounts/verify', views.Users.verify),

    path('dashboard', views.Dashboard.dashboard),
    path('test', views.Dashboard.test),
    path('exam_list', views.Dashboard.exam_list),
    path('settings', views.Dashboard.settings),

    path('examine', views.Examine.examine),
    path('examine/test', views.Examine.test),
    path('examine/add_test', views.Examine.add_test),
    path('examine/edit_test', views.Examine.edit_test),
    path('examine/uploaded_test_list', views.Examine.uploaded_test_list),
    path('examine/add_question', views.Examine.add_question),
    path('examine/question', views.Examine.question),
    path('examine/edit_question', views.Examine.edit_question),
    path('examine/result_list', views.Examine.result_list),

    path('exam', views.Exam.exam),
    path('start_exam', views.Exam.start_exam),
    path('exam/time', views.Exam.time),
    path('exam/answered', views.Exam.answered),
    path('exam/end', views.Exam.end_exam),
    path('result', views.Exam.result),
]
