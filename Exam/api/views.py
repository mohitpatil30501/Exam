import base64
import datetime
import json

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.messages.storage import session
from django.core.mail import send_mail
from django.http import JsonResponse
from django.shortcuts import render, redirect
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from Exam.settings import EMAIL_FROM, SECRET_KEY
from .models import UserInformation, Test, AnswerSheet, Question, Answer


def key_maker(username):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\xcfz\xfc\xdcF\xc1d\xc1\xb4\xfa5%\xe7\xa5\x14\x16',
        iterations=100000,
        backend=default_backend()
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(str(SECRET_KEY + username[::-1]).encode())))


class Users:
    def login(self):
        if self.method == "POST":
            username = self.POST.get('username')
            password = self.POST.get('password')

            if User.objects.filter(username=username).count() == 0:
                return JsonResponse({
                    'status': False,
                    'code': 404,
                    'data': {
                        'message': "Username Does Not Exist"
                    }
                })

            if not User.objects.filter(username=username).get().is_active:
                return JsonResponse({
                    'status': False,
                    'code': 404,
                    'data': {
                        'message': "User is Not Activated"
                    }
                })

            user = authenticate(self, username=username, password=password)
            if user is None:
                return JsonResponse({
                    'status': False,
                    'code': 404,
                    'data': {
                        'message': "Incorrect Password."
                    }
                })
            else:
                login(self, user)
                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'message': "User Authenticated"
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def register(self):
        if self.method == "POST":
            first_name = self.POST.get('first_name')
            last_name = self.POST.get('last_name')
            username = self.POST.get('username')
            email = self.POST.get('email')
            password = self.POST.get('password')

            if User.objects.filter(username=username).count() != 0:
                return JsonResponse({
                    'status': False,
                    'code': 404,
                    'data': {
                        'message': "Username Already Exists"
                    }
                })

            if User.objects.filter(email=email).count() != 0:
                return JsonResponse({
                    'status': False,
                    'code': 404,
                    'data': {
                        'message': "Email Already Exists"
                    }
                })

            try:
                user = User.objects.create_user(username=username, password=password, email=email,
                                                first_name=first_name, last_name=last_name)
                user.is_active = False
                user.save()
            except Exception as e:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': "Error While Creating User"
                    }
                })

            try:
                user_info = UserInformation.objects.create(user=user)
                user_info.save()
            except Exception as e:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': "Error While Creating User"
                    }
                })

            subject = "Email Verification"
            message = ''
            from_email = EMAIL_FROM
            recipient_list = [user.email, ]

            key = key_maker(user.username)
            data = {
                'id': str(user_info.id)
            }
            data = key.encrypt(json.dumps(data).encode()).decode()
            url = self.build_absolute_uri("/accounts/verify")

            html_message = '''
            <!DOCTYPE html>
            <html>
            <head>
            	<meta charset="utf-8">
            	<meta name="viewport" content="width=device-width, initial-scale=1">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>
            </head>
            <body>
                <h3>Email Verification</h3>
                <hr class="w-100">
                <form method="GET" action="''' + str(url) + '''">
                    <input type="text" name="username" value="''' + str(user.username) + '''" readonly style="display: none;" required>
                    <input type="text" name="data" value="''' + str(data) + '''" readonly style="display: none;" required>
                    <button type="submit" class="btn btn-primary">Click to Verify</button>
                </form>
                <hr class="w-100">
                <h2>If this mail is not relatable, Please Do not Click to Verify...!</h2>
            </body>
            </html>'''

            mail_status = send_mail(subject=subject, message=message, from_email=from_email,
                                    recipient_list=recipient_list,
                                    fail_silently=False, html_message=html_message)
            if not mail_status:
                user.delete()
                user_info.delete()
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': "Something error occurred, Try Again"
                    }
                })
            return JsonResponse({
                'status': True,
                'code': 200,
                'data': {
                    'message': "E-Mail Successfully Sent"
                }
            })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def logout(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                logout(self)
                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'message': "Logout Successful"
                    }
                })
            return JsonResponse({
                'status': True,
                'code': 200,
                'data': {
                    'message': "Logout Successful"
                }
            })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def forgot_password(self):
        if self.method == "POST":
            email = self.POST.get('email')
            if User.objects.filter(email=email).count() == 0:
                return JsonResponse({
                    'status': False,
                    'code': 404,
                    'data': {
                        'message': 'User Not Exist',
                    }
                })
            try:
                user = User.objects.filter(email=email).get()
                try:
                    if UserInformation.objects.filter(user=user).count() != 0:
                        user_info = UserInformation.objects.filter(user=user).get()
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 404,
                            'data': {
                                'message': 'User Found, But user not a Proper Member',
                            }
                        })
                except:
                    return JsonResponse({
                        'status': False,
                        'code': 404,
                        'data': {
                            'message': 'User Found, But user not a Student',
                        }
                    })
                key = key_maker(user.username)
                data = {
                    "id": str(user_info.id),
                    "username": user.username,
                    "valid_time": str(datetime.datetime.today() + datetime.timedelta(minutes=15))
                }
                data = key.encrypt(json.dumps(data).encode()).decode()
                url = self.build_absolute_uri("/accounts/reset_password")

                subject = "Reset Password"
                message = ''
                from_email = EMAIL_FROM
                recipient_list = [user.email, ]

                html_message = '''
                    <!DOCTYPE html>
                    <html>
                    <head>
                    </head>
                    <body>
                        <h1>Reset Password</h1>
                        <form method="GET" action="''' + str(url) + '''">
                            <input type="text" name="username" value="''' + str(user.username) + '''" readonly style="display: none;" required>
                            <input type="text" name="data" value="''' + str(data) + '''" readonly style="display: none;" required>
                            <button type="submit">Click to Reset</button>
                        </form>
                        <hr>
                        <p>Valid for 15 min only</p>
                        <h2>If this mail is not relatable, Please Do not Click to Verify...!</h2>
                    </body>
                    </html>
                    '''
                try:
                    send_mail(subject=subject, message=message, from_email=from_email, recipient_list=recipient_list,
                              fail_silently=False,
                              html_message=html_message)
                    return JsonResponse({
                        'status': True,
                        'code': 200,
                        'data': {
                            'message': 'Email Send Successfully',
                        }
                    })
                except:
                    return JsonResponse({
                        'status': False,
                        'code': 404,
                        'data': {
                            'message': 'Failed to Send Email',
                        }
                    })
            except:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "500 - Server Error",
                        'message': 'Data Extraction or Processing Problem',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def reset_password(self):
        if self.method == "GET":
            username = self.GET.get('username')
            data = self.GET.get('data')

            if username is None and data is None:
                if self.user.is_authenticated:
                    if UserInformation.objects.filter(user=self.user).count() != 0:
                        user_info = UserInformation.objects.filter(user=self.user).get()
                        return JsonResponse({
                            'status': True,
                            'code': 200,
                            'data': {
                                'id': user_info.id
                            }
                        })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "400 - BAD REQUEST",
                                'message': 'User Have No Role',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': 'LogIn First..!',
                        }
                    })
            else:
                key = key_maker(username)
                try:
                    data = key.decrypt(data.encode()).decode()
                    data = json.loads(data)

                    valid_time = datetime.datetime.strptime(data["valid_time"], '%Y-%m-%d %H:%M:%S.%f')

                    if datetime.timedelta(minutes=0,
                                          seconds=0) <= valid_time - datetime.datetime.today() <= datetime.timedelta(
                        minutes=15, seconds=0) and username == data['username']:
                        # change state to Active
                        try:
                            user = User.objects.filter(username=username).get()
                            if UserInformation.objects.filter(user=user).count() != 0:
                                user_info = UserInformation.objects.filter(user=user).get()
                            else:
                                return JsonResponse({
                                    'status': False,
                                    'code': 400,
                                    'data': {
                                        'error': "400 - BAD REQUEST",
                                        'message': 'User Have No Role',
                                    }
                                })
                            if str(user_info.id) != data['id']:
                                return JsonResponse({
                                    'status': False,
                                    'code': 400,
                                    'data': {
                                        'error': "400 - BAD REQUEST",
                                        'message': 'Link is Invalid',
                                    }
                                })
                            return JsonResponse({
                                'status': True,
                                'code': 200,
                                'data': {
                                    'id': user_info.id,
                                }
                            })
                        except:
                            return JsonResponse({
                                'status': False,
                                'code': 400,
                                'data': {
                                    'error': "400 - BAD REQUEST",
                                    'message': 'Unable to Extract user data...!',
                                }
                            })
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': 'Link is Not Valid...!',
                        }
                    })
                except:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': 'Something went wrong...!',
                        }
                    })
        elif self.method == "POST":
            id = self.POST.get('id')
            password = self.POST.get('password')
            try:
                if UserInformation.objects.filter(id=id).count() == 0:
                    return JsonResponse({
                        'status': False,
                        'code': 404,
                        'data': {
                            'message': 'User Not Found',
                        }
                    })
                else:
                    user_info = UserInformation.objects.filter(id=id).get()
                    user_info.user.set_password(password)
                    user_info.user.save()

                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'message': 'Reset Password Successful',
                    }
                })
            except:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'Unable to Extract user data...!',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def verify(self):
        if self.method == "POST":
            username = self.POST.get('username')
            data = self.POST.get('data')
            key = key_maker(username)
            try:
                data = json.loads(key.decrypt(data.encode()).decode())
                if User.objects.filter(username=username).count() == 0:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': "Username Does Not Exists"
                        }
                    })
                user = User.objects.get(username=username)
                if UserInformation.objects.filter(user=user).count() == 0:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': "Username Does Not Exists"
                        }
                    })
                user_info = UserInformation.objects.get(user=user)
                if str(user_info.id) != data['id']:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': "Url Data Not Matched"
                        }
                    })

                user.is_active = True
                user.save()
                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'data': {
                            'id': user_info.id,
                            'username': user.username,
                            'first_name': user.first_name,
                            'last_name': user.last_name,
                            'email': user.email,
                        },
                        'message': "Url Data Not Matched"
                    }
                })
            except Exception as e:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': "Invalid Url Provided"
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })


class Dashboard:
    def dashboard(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                recent_uploaded_test_list = []
                count = 0
                for test in list(Test.objects.filter(author=self.user, status=True).order_by('-created_on')):
                    recent_uploaded_test_list.append({
                        'id': test.id,
                        'title': test.title,
                        'subject': test.subject,
                    })
                    count += 1
                    if count >= 4:
                        break

                in_progress_test_list = []
                count = 0
                for answersheet in AnswerSheet.objects.filter(user=self.user, status=False).order_by('-created_on'):
                    in_progress_test_list.append({
                        'id': answersheet.test.id,
                        'title': answersheet.test.title,
                        'subject': answersheet.test.subject,
                    })
                    count += 1
                    if count >= 4:
                        break

                completed_test_list = []
                count = 0
                for answersheet in AnswerSheet.objects.filter(user=self.user, status=True).order_by('-created_on'):
                    completed_test_list.append({
                        'id': answersheet.test.id,
                        'title': answersheet.test.title,
                        'subject': answersheet.test.subject,
                    })
                    count += 1
                    if count >= 4:
                        break

                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'recent_uploaded_test_list': recent_uploaded_test_list,
                        'completed_test_list': completed_test_list,
                        'in_progress_test_list': in_progress_test_list
                    }
                })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def settings(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                first_name = self.POST.get('first_name')
                last_name = self.POST.get('last_name')
                if User.objects.filter(username=self.user.username).count() == 0:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': 'User Not Found',
                        }
                    })
                else:
                    self.user.first_name = first_name
                    self.user.last_name = last_name
                    self.user.save()
                    return JsonResponse({
                        'status': True,
                        'code': 200,
                        'data': {
                            'message': 'Change Successful',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User is Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def test(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                id = self.GET.get('id')
                if Test.objects.filter(id=id).count() != 0:
                    test = Test.objects.filter(id=id).get()
                    if AnswerSheet.objects.filter(user=self.user, test=test).count() == 0:
                        status = None
                    else:
                        answersheet = AnswerSheet.objects.filter(user=self.user, test=test).get()
                        status = answersheet.status
                    return JsonResponse({
                        'status': True,
                        'code': 200,
                        'data': {
                            'test': {
                                'id': test.id,
                                'author': test.author.username,
                                'title': test.title,
                                'subject': test.subject,
                                'description': test.description,
                                'total_questions': test.total_questions,
                                'marks_per_question': test.marks_per_question,
                                'total_time': test.total_time,
                                'from_date': test.from_date,
                                'till_date': test.till_date,
                            },
                            'status': status
                        }
                    })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "404 - Not Found",
                            'message': 'Not Found',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def exam_list(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                test_list = []
                for test in Test.objects.all():
                    if AnswerSheet.objects.filter(user=self.user, test=test).count() == 0:
                        test_list.append({
                            'id': test.id,
                            'name': test.title,
                            'subject': test.subject,
                            'status': None,
                        })
                    else:
                        answersheet = AnswerSheet.objects.filter(user=self.user, test=test).get()
                        test_list.append({
                            'id': test.id,
                            'name': test.title,
                            'subject': test.subject,
                            'status': answersheet.status,
                        })

                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'test_list': test_list
                    }
                })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })


class Examine:
    def examine(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    test_list = []
                    count = 0
                    for test in list(Test.objects.filter(author=self.user).order_by('-created_on')):
                        test_list.append({
                            'id': test.id,
                            'title': test.title,
                            'subject': test.subject,
                        })
                        count += 1
                        if count >= 4:
                            break

                    question_list = []
                    count = 0
                    for question in list(Question.objects.filter(author=self.user).order_by('-created_on')):
                        question_list.append({
                            'id': question.id,
                            'title': question.title,
                            'test': question.test.title,
                        })
                        count += 1
                        if count >= 4:
                            break
                    return JsonResponse({
                        'status': True,
                        'code': 200,
                        'data': {
                            'test_list': test_list,
                            'question_list': question_list,
                        }
                    })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def test(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    id = self.GET.get('id')
                    if Test.objects.filter(id=id).count() != 0:
                        test = Test.objects.filter(id=id).get()
                        question_list = []
                        for question in list(Question.objects.filter(test=test)):
                            question_list.append({
                                'id': question.id,
                                'title': question.title,
                            })

                        return JsonResponse({
                            'status': True,
                            'code': 200,
                            'data': {
                                'test': {
                                    'id': test.id,
                                    'author': test.author.username,
                                    'title': test.title,
                                    'subject': test.subject,
                                    'description': test.description,
                                    'total_questions': test.total_questions,
                                    'marks_per_question': test.marks_per_question,
                                    'total_time': test.total_time,
                                    'from_date': test.from_date,
                                    'till_date': test.till_date,
                                    'status': test.status,
                                    'created_on': test.created_on,
                                    'modified_on': test.modified_on,
                                },
                                'question_list': question_list
                            }
                        })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "404 - Not Found",
                                'message': 'Not Found',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def add_test(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    author = self.user
                    title = self.POST.get('title')
                    subject = self.POST.get('subject')
                    description = self.POST.get('description')
                    total_questions = self.POST.get('total_questions')
                    marks_per_question = self.POST.get('marks_per_question')
                    total_time = self.POST.get('total_time')
                    from_date_date = self.POST.get('from_date_date')
                    from_date_time = self.POST.get('from_date_time')
                    till_date_date = self.POST.get('till_date_date')
                    till_date_time = self.POST.get('till_date_time')
                    status = self.POST.get('status')

                    total_time = total_time.split(':')
                    total_time = datetime.timedelta(hours=int(total_time[0]), minutes=int(total_time[1]),
                                                    seconds=int(total_time[2]))

                    if from_date_date == '' or from_date_time == '':
                        from_date = None
                    else:
                        from_date = datetime.datetime.strptime(str(from_date_date) + ' ' + str(
                            datetime.datetime.strptime(from_date_time, '%I:%M %p').time()), '%m/%d/%Y %H:%M:%S')
                        from_date = datetime.datetime(from_date.year, from_date.month, from_date.day, from_date.hour,
                                                      from_date.minute, from_date.second)

                    if till_date_date == '' or till_date_time == '':
                        till_date = None
                    else:
                        till_date = datetime.datetime.strptime(str(till_date_date) + ' ' + str(
                            datetime.datetime.strptime(till_date_time, '%I:%M %p').time()), '%m/%d/%Y %H:%M:%S')
                        till_date = datetime.datetime(till_date.year, till_date.month, till_date.day, till_date.hour,
                                                      till_date.minute, till_date.second)

                    if status == "true":
                        status = True
                    else:
                        status = False

                    test = Test.objects.create(author=author, title=title, subject=subject, description=description,
                                               total_questions=total_questions, marks_per_question=marks_per_question,
                                               total_time=total_time, from_date=from_date, till_date=till_date,
                                               status=status)
                    test.save()
                    return JsonResponse({
                        'status': True,
                        'code': 200,
                        'data': {
                            'test': {
                                'id': test.id
                            }
                        }
                    })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def uploaded_test_list(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    test_list = []
                    for test in list(Test.objects.filter(author=self.user).order_by('-created_on')):
                        test_list.append({
                            'id': test.id,
                            'title': test.title,
                            'subject': test.subject,
                            'status': test.status,
                        })
                    return JsonResponse({
                        'status': True,
                        'code': 200,
                        'data': {
                            'test_list': test_list
                        }
                    })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def result_list(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    id = self.POST.get('id')
                    test_list = []
                    test = Test.objects.filter(id=id, author=self.user).get()
                    for answersheet in AnswerSheet.objects.filter(test=test):
                        correct_questions = []
                        wrong_questions = []
                        unsolved_questions = []

                        for answer in Answer.objects.filter(answer_sheet=answersheet):
                            if answer.attempted:
                                if answer.answer == answer.question.correct_answer:
                                    correct_questions.append(answer)
                                elif answer.answer != answer.question.correct_answer:
                                    wrong_questions.append(answer)
                            else:
                                unsolved_questions.append(answer)

                        data = {
                            'username': answersheet.user.username,
                            'obtained_marks': len(correct_questions) * test.marks_per_question,
                            'required_time': Exam.second_to_time(Exam.time_to_second(test.total_time) - Exam.time_to_second(answersheet.remaining_time)),
                        }

                        test_list.append(data)
                    return JsonResponse({
                        'status': True,
                        'code': 200,
                        'data': {
                            'test_list': test_list
                        }
                    })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def edit_test(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    id = self.POST.get('id')
                    title = self.POST.get('title')
                    subject = self.POST.get('subject')
                    description = self.POST.get('description')
                    total_questions = self.POST.get('total_questions')
                    marks_per_question = self.POST.get('marks_per_question')
                    total_time = self.POST.get('total_time')
                    from_date_date = self.POST.get('from_date_date')
                    from_date_time = self.POST.get('from_date_time')
                    till_date_date = self.POST.get('till_date_date')
                    till_date_time = self.POST.get('till_date_time')
                    status = self.POST.get('status')

                    total_time = total_time.split(':')
                    total_time = datetime.timedelta(hours=int(total_time[0]), minutes=int(total_time[1]),
                                                    seconds=int(total_time[2]))

                    if from_date_date == '' or from_date_time == '':
                        from_date = None
                    else:
                        from_date = datetime.datetime.strptime(str(from_date_date) + ' ' + str(
                            datetime.datetime.strptime(from_date_time, '%I:%M %p').time()), '%m/%d/%Y %H:%M:%S')
                        from_date = datetime.datetime(from_date.year, from_date.month, from_date.day, from_date.hour,
                                                      from_date.minute, from_date.second)

                    if till_date_date == '' or till_date_time == '':
                        till_date = None
                    else:
                        till_date = datetime.datetime.strptime(str(till_date_date) + ' ' + str(
                            datetime.datetime.strptime(till_date_time, '%I:%M %p').time()), '%m/%d/%Y %H:%M:%S')
                        till_date = datetime.datetime(till_date.year, till_date.month, till_date.day, till_date.hour,
                                                      till_date.minute, till_date.second)

                    if status == "true":
                        status = True
                    else:
                        status = False

                    if Test.objects.filter(id=id).count() != 0:
                        test = Test.objects.filter(id=id).get()
                        test.title = title
                        test.subject = subject
                        test.description = description
                        test.total_questions = total_questions
                        test.marks_per_question = marks_per_question
                        test.total_time = total_time
                        test.from_date = from_date
                        test.till_date = till_date
                        test.status = status
                        test.save()
                        return JsonResponse({
                            'status': True,
                            'code': 200,
                            'data': {
                                'test': {
                                    'id': test.id
                                }
                            }
                        })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "404 - Not Found",
                                'message': 'Test Not Found',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        elif self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    id = self.GET.get('id')
                    if Test.objects.filter(id=id).count() != 0:
                        test = Test.objects.filter(id=id).get()
                        return JsonResponse({
                            'status': True,
                            'code': 200,
                            'data': {
                                'test': {
                                    'id': test.id,
                                    'author': test.author.username,
                                    'title': test.title,
                                    'subject': test.subject,
                                    'description': test.description,
                                    'total_questions': test.total_questions,
                                    'marks_per_question': test.marks_per_question,
                                    'total_time': test.total_time,
                                    'from_date': test.from_date,
                                    'till_date': test.till_date,
                                    'status': test.status,
                                    'created_on': test.created_on,
                                    'modified_on': test.modified_on,
                                }
                            }
                        })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "404 - Not Found",
                                'message': 'Not Found',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def add_question(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    id = self.POST.get('id')
                    author = self.user
                    title = self.POST.get('title')
                    question = self.POST.get('question')
                    option_1 = self.POST.get('option_1')
                    option_2 = self.POST.get('option_2')
                    option_3 = self.POST.get('option_3')
                    option_4 = self.POST.get('option_4')
                    correct_answer = self.POST.get('correct_answer')
                    answer_key_description = self.POST.get('answer_key_description')

                    if Test.objects.filter(id=id).count() != 0:
                        test = Test.objects.filter(id=id).get()
                        question = Question.objects.create(author=author, title=title, test=test, question=question,
                                                           option_1=option_1, option_2=option_2, option_3=option_3,
                                                           option_4=option_4, correct_answer=correct_answer,
                                                           answer_key_description=answer_key_description)
                        question.save()
                        return JsonResponse({
                            'status': True,
                            'code': 200,
                            'data': {
                                'question': {
                                    'id': question.id
                                }
                            }
                        })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "404 - Not Found",
                                'message': 'Test Not Found',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def question(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    id = self.GET.get('id')
                    if Question.objects.filter(id=id).count() != 0:
                        question = Question.objects.filter(id=id).get()
                        return JsonResponse({
                            'status': True,
                            'code': 200,
                            'data': {
                                'question': {
                                    'id': question.id,
                                    'author': question.author.username,
                                    'title': question.title,
                                    'test_id': question.test.id,
                                    'test': question.test.title,
                                    'question': question.question,
                                    'option_1': question.option_1,
                                    'option_2': question.option_2,
                                    'option_3': question.option_3,
                                    'option_4': question.option_4,
                                    'correct_answer': question.correct_answer,
                                    'answer_key_description': question.answer_key_description,
                                    'created_on': question.created_on,
                                    'modified_on': question.modified_on,
                                }
                            }
                        })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "404 - Not Found",
                                'message': 'Not Found',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def edit_question(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    id = self.POST.get('id')
                    title = self.POST.get('title')
                    question_text = self.POST.get('question')
                    option_1 = self.POST.get('option_1')
                    option_2 = self.POST.get('option_2')
                    option_3 = self.POST.get('option_3')
                    option_4 = self.POST.get('option_4')
                    correct_answer = self.POST.get('correct_answer')
                    answer_key_description = self.POST.get('answer_key_description')

                    if Question.objects.filter(id=id).count() != 0:
                        question = Question.objects.filter(id=id).get()
                        question.title = title
                        question.question = question_text
                        question.option_1 = option_1
                        question.option_2 = option_2
                        question.option_3 = option_3
                        question.option_4 = option_4
                        question.correct_answer = correct_answer
                        question.answer_key_description = answer_key_description
                        question.save()
                        return JsonResponse({
                            'status': True,
                            'code': 200,
                            'data': {
                                'question': {
                                    'id': question.id
                                }
                            }
                        })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "404 - Not Found",
                                'message': 'Test Not Found',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        elif self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    id = self.GET.get('id')
                    if Question.objects.filter(id=id).count() != 0:
                        question = Question.objects.filter(id=id).get()
                        return JsonResponse({
                            'status': True,
                            'code': 200,
                            'data': {
                                'question': {
                                    'id': question.id,
                                    'author': question.author.username,
                                    'title': question.title,
                                    'test_id': question.test.id,
                                    'test': question.test.title,
                                    'question': question.question,
                                    'option_1': question.option_1,
                                    'option_2': question.option_2,
                                    'option_3': question.option_3,
                                    'option_4': question.option_4,
                                    'correct_answer': question.correct_answer,
                                    'answer_key_description': question.answer_key_description,
                                    'created_on': question.created_on,
                                    'modified_on': question.modified_on,
                                }
                            }
                        })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "404 - Not Found",
                                'message': 'Not Found',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "403 - Forbidden",
                            'message': 'Access Denied',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })


class Exam:

    @staticmethod
    def time_to_second(time):
        time = str(time).split(':')
        seconds = (int(time[0]) * 3600) + (int(time[1]) * 60) + (int(time[2]))
        return seconds

    @staticmethod
    def second_to_time(seconds):
        return datetime.timedelta(seconds=int(seconds))

    def exam(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                user = self.user
                exam_session = self.session.get('exam')
                test = exam_session['test']
                answersheet = exam_session['answersheet']

                if Test.objects.filter(id=test).count() != 0:
                    test = Test.objects.filter(id=test).get()
                    if AnswerSheet.objects.filter(id=answersheet, user=user, test=test).count() == 0:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "400 - BAD REQUEST",
                                'message': 'Invalid Session',
                            }
                        })
                    else:
                        answersheet = AnswerSheet.objects.filter(id=answersheet, user=user, test=test).get()

                    test_details = {
                        'total_questions': test.total_questions,
                        'marks_per_question': test.marks_per_question,
                        'total_time': test.total_time,
                        'remaining_time': answersheet.remaining_time,
                        'remaining_warning': answersheet.remaining_warning,
                        'last_question': answersheet.last_question,
                    }
                    test_data = []
                    for question in Question.objects.filter(test=test):
                        answer = Answer.objects.filter(user=user, answer_sheet=answersheet, question=question).get()
                        test_data.append({
                            'id': question.id,
                            'question': question.question,
                            'option_1': question.option_1,
                            'option_2': question.option_2,
                            'option_3': question.option_3,
                            'option_4': question.option_4,
                            'answer_id': answer.id,
                            'question_number': answer.question_number,
                            'answer': answer.answer,
                            'attempted': answer.attempted,
                        })

                    data = []
                    for i in range(1, test.total_questions+1):
                        for question in test_data:
                            if i == question['question_number']:
                                data.append(question)
                    return JsonResponse({
                        'status': True,
                        'code': 200,
                        'data': {
                            'details': test_details,
                            'test': data
                        }
                    })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': 'Test Not Found',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def start_exam(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                user = self.user
                id = self.POST.get('id')

                if Test.objects.filter(id=id).count() != 0:
                    test = Test.objects.filter(id=id).get()
                    if AnswerSheet.objects.filter(user=user, test=test).count() == 0:
                        answersheet = AnswerSheet.objects.create(user=user, test=test, remaining_time=test.total_time)
                        answersheet.save()
                    else:
                        answersheet = AnswerSheet.objects.filter(user=user, test=test).get()
                        answersheet.save()

                    if not answersheet.status:
                        if datetime.datetime.today() - (datetime.datetime(year=answersheet.start_time.year, month=answersheet.start_time.month, day=answersheet.start_time.day, hour=answersheet.start_time.hour, minute=answersheet.start_time.minute, second=answersheet.start_time.second) + datetime.timedelta(seconds=Exam.time_to_second(test.total_time))) >= datetime.timedelta(minutes=20):
                            answersheet.status = True
                            answersheet.save()
                            return JsonResponse({
                                'status': False,
                                'code': 400,
                                'data': {
                                    'error': "400 - BAD REQUEST",
                                    'message': 'Exam already Expired, pause is about 20 Min',
                                }
                            })
                        else:
                            self.session['exam'] = {
                                'test': str(test.id),
                                'answersheet': str(answersheet.id),
                                'time': int(Exam.time_to_second(answersheet.remaining_time))
                            }
                            return JsonResponse({
                                'status': True,
                                'code': 200,
                                'data': {
                                    'id': test.id
                                }
                            })
                    else:
                        return JsonResponse({
                            'status': False,
                            'code': 400,
                            'data': {
                                'error': "400 - BAD REQUEST",
                                'message': 'Exam already Submitted',
                            }
                        })
                else:
                    return JsonResponse({
                        'status': False,
                        'code': 400,
                        'data': {
                            'error': "400 - BAD REQUEST",
                            'message': 'Test Not Found',
                        }
                    })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def time(self):
        if self.method == "POST":
            exam = self.session.get('exam')
            exam['time'] -= 1
            self.session['exam'] = exam

            answersheet = AnswerSheet.objects.filter(id=exam['answersheet']).get()
            answersheet.remaining_time = Exam.second_to_time(self.session['exam'].get('time'))
            answersheet.save()

            if self.session.get('exam')['time'] < 0:
                answersheet.status = True
                answersheet.save()
                exam = self.session.get('exam')
                exam['time'] = 0
                self.session['exam'] = exam
                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'time': 0,
                    }
                })
            return JsonResponse({
                'status': True,
                'code': 200,
                'data': {
                    'time': self.session.get('exam')['time'],
                }
            })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def answered(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                question = self.POST.get('question')
                answer_id = self.POST.get('answer_id')
                answer_option = self.POST.get('answer')

                question = Question.objects.filter(id=question).get()
                answer = Answer.objects.filter(question=question, id=answer_id).get()
                answer.answer = int(answer_option)
                answer.attempted = True
                answer.save()
                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'question_number': answer.question_number,
                        'answer': answer.answer
                    }
                })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def end_exam(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                user = self.user
                exam = self.session.get('exam')
                test = Test.objects.filter(id=exam['test']).get()
                answersheet = AnswerSheet.objects.filter(id=exam['answersheet'], user=user, test=test).get()
                answersheet.end_time = datetime.datetime.now()
                answersheet.status = True
                answersheet.save()

                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': {
                        'id': test.id
                    }
                })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })

    def result(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                user = self.user
                id = self.POST.get('id')

                correct_questions = []
                wrong_questions = []
                unsolved_questions = []

                test = Test.objects.filter(id=id).get()
                answersheet = AnswerSheet.objects.filter(user=user, test=test).get()
                for answer in Answer.objects.filter(answer_sheet=answersheet, user=user):
                    if answer.attempted:
                        if answer.answer == answer.question.correct_answer:
                            correct_questions.append(answer)
                        elif answer.answer != answer.question.correct_answer:
                            wrong_questions.append(answer)
                    else:
                        unsolved_questions.append(answer)
                data = {
                    'test': {
                        'id': test.id,
                        'title': test.title,
                        'subject': test.subject
                    },
                    'obtained_marks': len(correct_questions) * test.marks_per_question,
                    'total_marks': (len(correct_questions) + len(wrong_questions) + len(unsolved_questions)) * test.marks_per_question,
                    'correct_questions': len(correct_questions),
                    'wrong_questions': len(wrong_questions),
                    'unsolved_questions': len(unsolved_questions),
                }

                return JsonResponse({
                    'status': True,
                    'code': 200,
                    'data': data
                })
            else:
                return JsonResponse({
                    'status': False,
                    'code': 400,
                    'data': {
                        'error': "400 - BAD REQUEST",
                        'message': 'User Not Logged In',
                    }
                })
        else:
            return JsonResponse({
                'status': False,
                'code': 400,
                'data': {
                    'error': "400 - BAD REQUEST",
                    'message': 'Wrong Request Method Used',
                }
            })
