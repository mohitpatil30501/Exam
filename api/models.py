import random
import uuid
import datetime

from django.contrib.auth.models import User
from django.db import models


class LoginAttempt(models.Model):
    """
    Model to track login attempts for account lockout functionality
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_attempts')
    timestamp = models.DateTimeField(auto_now_add=True)
    successful = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.user.username} - {'Success' if self.successful else 'Failed'} at {self.timestamp}"


def get_uuid():
    while True:
        id = uuid.uuid4()
        if UserInformation.objects.filter(id=id).count() == 0:
            return id


class UserInformation(models.Model):
    id = models.UUIDField(default=get_uuid, primary_key=True, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.user.username)


def get_uuid_test():
    while True:
        id = uuid.uuid4()
        if Test.objects.filter(id=id).count() == 0:
            return id


class Test(models.Model):
    id = models.UUIDField(default=get_uuid_test, primary_key=True, unique=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    subject = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True, default=None)
    total_questions = models.IntegerField(default=0)
    marks_per_question = models.FloatField(default=1.0)
    total_time = models.DurationField()
    from_date = models.DateTimeField(default=None, blank=True, null=True)
    till_date = models.DateTimeField(default=None, blank=True, null=True)
    status = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True)
    modified_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.title)


def get_uuid_question():
    while True:
        id = uuid.uuid4()
        if Question.objects.filter(id=id).count() == 0:
            return id


class Question(models.Model):
    id = models.UUIDField(default=get_uuid_question, primary_key=True, unique=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    title = models.CharField(max_length=200, default=None)
    question = models.TextField()
    option_1 = models.TextField()
    option_2 = models.TextField()
    option_3 = models.TextField()
    option_4 = models.TextField()
    correct_answer = models.IntegerField()
    answer_key_description = models.TextField(default=None, blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True)
    modified_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.title)


def get_uuid_answer_sheet():
    while True:
        id = uuid.uuid4()
        if AnswerSheet.objects.filter(id=id).count() == 0:
            return id


class AnswerSheet(models.Model):
    id = models.UUIDField(default=get_uuid_answer_sheet, primary_key=True, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    remaining_time = models.DurationField()
    remaining_warning = models.IntegerField(default=5)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(default=None, null=True, blank=True)
    last_question = models.IntegerField(default=1)
    status = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True)
    modified_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if (Answer.objects.filter(user=self.user, answer_sheet=self).count() == 0) or (Answer.objects.filter(user=self.user, answer_sheet=self).count() < self.test.total_questions):
            questions_list = list(Question.objects.filter(test=self.test))
            random.shuffle(questions_list)
            question_count = 1
            for question in questions_list:
                if Answer.objects.filter(user=self.user, answer_sheet=self, question=question).count() == 0:
                    answer = Answer.objects.create(user=self.user, answer_sheet=self, question=question, question_number=question_count)
                    answer.save()
                else:
                    answer = Answer.objects.filter(user=self.user, answer_sheet=self, question=question).get()
                    answer.question_number = question_count
                    answer.save()
                question_count += 1


def get_uuid_answer():
    while True:
        id = uuid.uuid4()
        if Answer.objects.filter(id=id).count() == 0:
            return id


class Answer(models.Model):
    id = models.UUIDField(default=get_uuid_answer, primary_key=True, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    answer_sheet = models.ForeignKey(AnswerSheet, on_delete=models.CASCADE)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    question_number = models.IntegerField()
    answer = models.IntegerField(default=None, blank=True, null=True)
    bookmark = models.BooleanField(default=False)
    attempted = models.BooleanField(default=False)
    time = models.DateTimeField(auto_now=True)
    created_on = models.DateTimeField(auto_now_add=True)
    modified_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)


def get_uuid_reset_token():
    while True:
        id = uuid.uuid4()
        if PasswordResetToken.objects.filter(token=id).count() == 0:
            return id


class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=get_uuid_reset_token, primary_key=True, unique=True)
    is_used = models.BooleanField(default=False)
    expiry_date = models.DateTimeField()
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.token}"
    
    def is_valid(self):
        return not self.is_used and self.expiry_date > datetime.datetime.now()
