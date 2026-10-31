// TEST DATA FIXTURE - VULNERABLE JAVASCRIPT PATTERNS

function renderUserData(userInput) {
    // Unsafe dynamic code evaluation (ENT-JS-002)
    const result = eval("2 + " + userInput);

    const fn = new Function("arg", "return " + userInput);

    // Unsafe DOM manipulation (ENT-JS-003)
    const container = document.getElementById("content");
    container.innerHTML = "<div>" + userInput + "</div>";
    document.write("<p>" + userInput + "</p>");
}
