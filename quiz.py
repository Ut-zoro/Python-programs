# Questions, Options, and Answers
questions = [
    "What is the capital of Italy?",
    "Which gas do plants absorb from the atmosphere?",
    "Which number is the smallest prime number?",
    "Who painted the Mona Lisa?",
    "Which programming language is known for its snake logo?"
]

options = [
    ["a) Rome", "b) Paris", "c) Madrid", "d) Berlin"],
    ["a) Oxygen", "b) Hydrogen", "c) Carbon Dioxide", "d) Nitrogen"],
    ["a) 0", "b) 1", "c) 2", "d) 3"],
    ["a) Picasso", "b) Leonardo da Vinci", "c) Van Gogh", "d) Michelangelo"],
    ["a) Python", "b) Java", "c) C++", "d) HTML"]
]

answers = ['a', 'c', 'c', 'b', 'a']

# Initialize score
score = 0

# Quiz loop
for i in range(5):
    print("\n" + questions[i])
    for opt in options[i]:
        print(opt)
    user_input = input("Enter your answer (a/b/c/d): ").lower()

    if user_input == answers[i]:
        print("Correct!")
        score += 1
    else:
        print(f"Wrong. The correct answer was: {answers[i]})")

# Final result
print("\n=== Quiz Completed ===")
print(f"Your Score: {score}/5")

# Optional performance feedback
if score == 5:
    print("Perfect score! Great job!")
elif score >= 3:
    print("Good effort!")
else:
    print("Keep practicing!")
