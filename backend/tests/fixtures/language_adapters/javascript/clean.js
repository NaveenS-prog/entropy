// TEST DATA FIXTURE - CLEAN JAVASCRIPT PATTERNS

function renderUserDataSafe(userInput) {
    // Safe DOM manipulation via textContent
    const container = document.getElementById("content");
    container.textContent = userInput;

    // Safe JSON parsing
    const parsed = JSON.parse(userInput);
    return parsed;
}
