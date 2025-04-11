from openai import OpenAI # type: ignore
from decouple import config # type: ignore

# Initialize OpenAI client
api_key = MY_SECRET_API_KEY = config('MY_SECRET_API_KEY')
client = OpenAI(api_key=api_key)

def generate_questions(topic, num_questions, difficulty):
    prompt = (
    f"Generate {num_questions} multiple-choice questions on {topic}.\n"
    f"Each question must be in this format:\n"
    f"Question text\n"
    f"A. Option A\n"
    f"B. Option B\n"
    f"C. Option C\n"
    f"D. Option D\n"
    f"Answer: A\n\n"
    f"Make them {difficulty} level. Keep formatting exactly as shown."
    )


    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a quiz question generator."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1500
        )

        content = response.choices[0].message.content
        return parse_questions(content)
    except Exception as e:
        return [{"error": str(e)}]

def parse_questions(text):
    questions = []
    blocks = text.strip().split("\n\n")

    for block in blocks:
        lines = block.strip().split('\n')
        if len(lines) < 6:
            continue  # Skip incomplete blocks

        question = lines[0].strip()
        options = {}
        correct = None

        for line in lines[1:]:
            line = line.strip()
            if line.startswith("A."):
                options['A'] = line[2:].strip()
            elif line.startswith("B."):
                options['B'] = line[2:].strip()
            elif line.startswith("C."):
                options['C'] = line[2:].strip()
            elif line.startswith("D."):
                options['D'] = line[2:].strip()
            elif "Answer:" in line:
                correct = line.split("Answer:")[-1].strip()

        if question and options and correct in options:
            questions.append({
                'question': question,
                'options': options,
                'correct': correct
            })

    return questions
