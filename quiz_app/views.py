from django.shortcuts import render, redirect
from .forms import QuizSettingsForm
from .utils import generate_questions
import uuid
from datetime import datetime
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from django.http import JsonResponse
from django.contrib import messages
from django.utils.timezone import now as timezone_now
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.conf import settings
import requests
from django.contrib.auth.decorators import login_required
import random
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from .models import Register
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils.safestring import mark_safe

def landing_page(request):
    if request.method == 'POST':
        form = QuizSettingsForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            questions = generate_questions(
                topic=data['topic'],
                num_questions=data['num_questions'],
                difficulty=data['difficulty']
            )
            if not questions or len(questions) < data['num_questions']:
                actual_count = len(questions) if questions else 0
                messages.error(request, f"Only {actual_count} question(s) are generated out of {data['num_questions']}. Please try again.")
                return render(request, 'quiz_app/landing.html', {'form': form})


            session_id = str(uuid.uuid4())
            request.session['quiz'] = {
                'session_id': session_id,
                'topic': data['topic'],
                'difficulty': data['difficulty'],
                'num_questions': data['num_questions'],
                'total_time': data['timer'] * 60,  # store full time in seconds
                'start_time': timezone.now().isoformat(),  # store current time
                'negative_marking': data.get('negative_marking', False),
                'questions': questions,
                'answers': {},
                'current_question': 0,
            }
            return redirect('quiz')
        else:
            messages.error(request, "Invalid Data. Please try again.")
            return render(request, 'quiz_app/landing.html', {'form': form})
    else:
        form = QuizSettingsForm()

    return render(request, 'quiz_app/landing.html', {'form': form})



def quiz_page(request):
    quiz_data = request.session.get('quiz')
    if not quiz_data:
        return redirect('landing')

    # Calculate total remaining time
    start_time = parse_datetime(quiz_data['start_time'])
    now = timezone.now()
    elapsed_seconds = (now - start_time).total_seconds()
    remaining_time = quiz_data['total_time'] - int(elapsed_seconds)

    if remaining_time <= 0:
        return redirect('result')

    # Initialize time_per_question if not exists
    if 'time_per_question' not in quiz_data:
        quiz_data['time_per_question'] = {}

    if request.method == 'POST':
        action = request.POST.get('action')
        selected_option = request.POST.get('selected_option')
        current_index = quiz_data['current_question']

        # Save answer
        if selected_option:
            quiz_data['answers'][str(current_index)] = selected_option

        # ⏱️ Track time per question
        if 'question_start_time' in quiz_data:
            question_start = parse_datetime(quiz_data['question_start_time'])
            time_spent = (timezone.now() - question_start).total_seconds()
            quiz_data['time_per_question'][str(current_index)] = quiz_data['time_per_question'].get(str(current_index), 0) + time_spent

        # Handle navigation
        if action == 'next':
            quiz_data['current_question'] += 1
        elif action == 'previous':
            quiz_data['current_question'] -= 1
        elif action == 'quit':
            request.session['quiz'] = quiz_data
            return redirect('result')

        # Save new question start time
        quiz_data['question_start_time'] = timezone.now().isoformat()
        request.session['quiz'] = quiz_data

    # Set initial question start time if not already set
    if 'question_start_time' not in quiz_data:
        quiz_data['question_start_time'] = timezone.now().isoformat()
        request.session['quiz'] = quiz_data

    # Validate bounds and handle end-of-quiz
    current_index = quiz_data['current_question']
    if current_index < 0:
        current_index = 0
    elif current_index >= quiz_data['num_questions']:
        return redirect('result')  # Quiz is over

    quiz_data['current_question'] = current_index
    request.session['quiz'] = quiz_data

    # Load question
    question_data = quiz_data['questions'][current_index]
    saved_answer = quiz_data['answers'].get(str(current_index), '')

    return render(request, 'quiz_app/quiz.html', {
        'question_index': current_index + 1,
        'question_data': question_data,
        'total': quiz_data['num_questions'],
        'timer': remaining_time,
        'saved_answer': saved_answer,
    })




def result_page(request):
    quiz_data = request.session.get('quiz')
    if not quiz_data:
        return redirect('landing')

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'home':
            request.session.flush()
            return redirect('landing')
        elif action == 'retake':
            try:
                topic = quiz_data['topic']
                num_questions = quiz_data['num_questions']
                difficulty = quiz_data['difficulty']
                timer = quiz_data['total_time'] // 60

                new_quiz = {
                    'session_id': str(uuid.uuid4()),
                    'topic': topic,
                    'difficulty': difficulty,
                    'num_questions': num_questions,
                    'total_time': timer * 60,
                    'start_time': timezone.now().isoformat(),
                    'questions': generate_questions(topic, num_questions, difficulty),
                    'answers': {},
                    'current_question': 0,
                }

                request.session['quiz'] = new_quiz
                return redirect('quiz')
            except Exception:
                messages.error(request, "Something went wrong. Please try again.")
                return redirect('landing')

    correct = 0
    wrong = 0
    unanswered = 0
    total = quiz_data['num_questions']
    negative_marking = quiz_data.get('negative_marking', False)
    time_per_question = quiz_data.get('time_per_question', {})
    questions_with_answers = []

    for index, question in enumerate(quiz_data['questions']):
        selected = quiz_data['answers'].get(str(index))
        correct_option = question['correct']
        time_taken = round(time_per_question.get(str(index), 0), 2)

        if selected is None:
            unanswered += 1
            is_correct = False
        else:
            is_correct = selected == correct_option
            if is_correct:
                correct += 1
            else:
                wrong += 1

        questions_with_answers.append({
            'question_text': question['question'],
            'options': question['options'],
            'correct_option': correct_option,
            'selected_option': selected,
            'is_correct': is_correct,
            'time_taken': time_taken,
        })

    if negative_marking:
        score = round(((correct - 0.25 * wrong) / total) * 100, 2)
    else:
        score = round((correct / total) * 100, 2)
    if request.user.is_authenticated:
        subject = f"Quiz Completed: {quiz_data['topic']}"
        message = f"""
        Dear User,

        Congratulations! You have successfully completed the {quiz_data['topic']} quiz.

        Here are your results:
        - Total Questions: {quiz_data['num_questions']}
        - Correct Answers: {correct}
        - Wrong Answers: {wrong}
        - Unanswered: {unanswered}
        - Your Score: {score}%

        """

        if negative_marking:
            message += f"""
            Note: Negative marking was applied. For each wrong answer, 0.25 points were subtracted from your score.
            """

        message += """
        Thank you for participating!

        Best regards,
        The Quiz Team
        """
        from_email = settings.DEFAULT_FROM_EMAIL
        send_mail(subject, message, from_email, [request.user.email], fail_silently=False)
    else:
        link = '<a href="/login/">Login</a>'
        messages.info(request, mark_safe(f'👉{link} to receive your quiz results via email.'))
    return render(request, 'quiz_app/result.html', {
        'score': score,
        'correct': correct,
        'wrong': wrong,
        'unanswered': unanswered,
        'total': total,
        'questions_with_answers': questions_with_answers,
        'negative_marking': negative_marking,
    })

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        recaptcha_response = request.POST.get("g-recaptcha-response")

        # Verify reCAPTCHA with Google
        secret_key = "6Le_vhMrAAAAAIUxM_6nv8PyQMVI7tQEZdMJjQlJ"
        data = {
            "secret": secret_key,
            "response": recaptcha_response
        }
        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        response = requests.post(verify_url, data=data).json()

        if response.get("success"):
            # reCAPTCHA verified, proceed with authentication logic
            # Check if the user is using email or username
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                # if remember_me:
                #     request.session.set_expiry(2592000)  # 30 days
                # else:
                #     request.session.set_expiry(0)
                return redirect("landing")

            else:
                messages.error(request, "Invalid credentials, please try again.")
                return redirect('login')
        else:
            messages.error(request, 'reCAPTCHA verification failed. Try again.')
            return redirect('login')


    return render(request, "quiz_app/login.html")

def logout_view(request):
    logout(request)
    return redirect('login')

def register(request):
    if request.method == 'POST':
        # Get the cleaned data from the form
        full_name = request.POST['full_name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        user_otp = request.POST['otp']
        session_otp = request.session.get('otp')
        session_email = request.session.get('email')


        if User.objects.filter(Q(username=email) | Q(email=email)).exists():
            messages.error(request, "email already exists.")
            return render(request, 'quiz_app/register.html', {'form_data': request.POST})

        if email != session_email:
            messages.error(request, "Verify Email.")
            return render(request, 'quiz_app/register.html', {'form_data': request.POST})
        if user_otp != session_otp:
            messages.error(request, "Incorrect OTP.")
            return render(request, 'quiz_app/register.html', {'form_data': request.POST})
        if password != confirm_password:
            messages.error(request, "password mismatch.")
            return render(request, 'quiz_app/register.html', {'form_data': request.POST})


        else:
            user = User.objects.create_user(
                username=email,
                first_name = request.POST['full_name'].split(' ')[0],
                last_name=' '.join(request.POST['full_name'].split(' ')[1:]),
                email=email,
                password=password  # This will automatically hash the password
            )

            register = Register.objects.create(
                full_name = full_name,
                email=email,
                password=password
            )
            subject = "Welcome to Our QuizForAll"
            message = (
                    f"Hi {full_name},\n\n"
                    f"Welcome to our QuizForAll platform! Your has been successfully registered.\n\n"
                    f"Best regards,\n"
                    f"SidhuManchala"
            )
            from_email = settings.DEFAULT_FROM_EMAIL
            send_mail(subject, message, from_email, [email], fail_silently=False)
		     #  messages.success(request, "Registration successful! Check your email for details.")
            # Redirect to the login page after successful registration
            messages.success(request, "Successfully registered!")
            return redirect('login')


    return render(request, 'quiz_app/register.html')


@csrf_exempt
def send_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email', '').strip()

        if not email:
            return JsonResponse({'error': 'Email is required'}, status=400)

        otp = str(random.randint(100000, 999999))

        request.session['otp'] = otp
        request.session['email'] = email

        send_mail(
            'Your OTP Code',
            f'Your OTP is: {otp}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        return JsonResponse({'message': otp})



