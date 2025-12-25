var manageGeneratedKeyHtml = `<button class="btn btn-sm btn-circle m-1" onclick="copyGeneratedKeyToClipboard()"><i class="fa-solid fa-clipboard"></i></button><button class="btn btn-sm btn-circle" onclick="saveGeneratedKeyInBrowser()"><i class="fa-regular fa-window-maximize"></i></button>`;
var showKeyStatusMessageTimer, displayMessageTime = 2500;

function htmlEntities(text) {
    return text.replace(/[\u00A0-\u9999<>\&"']/g, function (i) {
        return '&#' + i.charCodeAt(0) + ';';
    });
}

function showSuccessAlert(text) {
    var alertId = 'alert-' + Date.now();
    var alertHtml = `<div class="mb-2 mx-3" id="${alertId}" onclick="$(this).remove()">
                        <div role="alert" class="alert alert-success">
                            <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none"
                                viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span>${text}</span>
                        </div>
                    </div>`;
    $('#alert-container').append(alertHtml);
    setTimeout(function () {
        $('#' + alertId).remove();
    }, displayMessageTime);
}

function generateAPIKey() {
    var recaptchaResponse = '';
    if (typeof grecaptcha !== 'undefined') {
        var recaptchaResponse = grecaptcha.getResponse();
        if (!recaptchaResponse){
            $("#genTokenResponse").html('<span class="text-error font-bold">You have to solve the reCAPTCHA challenge first!</span>');
            return;
        }
    }

    $("#genTokenResponse").html(`<span class="loading loading-spinner"></span>`);
    $.post({
        url: "/api/generate-key",
        data: 'recaptcha_response=' + recaptchaResponse,
        success: function (generationResponse) {
            if (generationResponse.status == 'success') {
                $("#genTokenResponse").html(`Here is your API key: <span class="font-bold mr-3" id="generated-api-key">${generationResponse.key}</span>` + manageGeneratedKeyHtml);
            }
            else {
                $("#genTokenResponse").html(`<span class="text-error font-bold">Encountered an error: ${generationResponse.msg}</span>`);
            }
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;
            console.log(errorMsg);
            $("#genTokenResponse").html('<span class="text-error font-bold">Error: encountered an HTTP error, see JS console for details.</span>');
        }
    });
}

function checkCurrentAPIKeyStatus() {
    var key = localStorage.getItem('apiKey');
    if (key === undefined || key == null || !key) {
        $('#check-api-key-result').html('<span class="text-error">No saved key found in this browser</span>');
        clearTimeout(showKeyStatusMessageTimer);
        showKeyStatusMessageTimer = setTimeout(function () {
            $('#check-api-key-result').html('');
        }, displayMessageTime);
        return;
    }

    checkAPIKeyStatus(key);
}

function checkAPIKeyStatus(key) {
    if (key === undefined || key == null || !key)
        key = $('#check-api-key').val().trim();
    if (key === undefined || key == null || !key) {
        $('#check-api-key-result').html('<span class="text-error">No key was provided</span>');
        clearTimeout(showKeyStatusMessageTimer);
        showKeyStatusMessageTimer = setTimeout(function () {
            $('#check-api-key-result').html('');
        }, displayMessageTime);
        return;
    }

    $.post({
        url: "/api/check-key-status",
        data: `{"key": "${key}"}`,
        contentType : 'application/json',
        success: function (statusResponse) {
            if (statusResponse.status == 'valid')
                $('#check-api-key-result').html('<span class="text-success"> Key is ' + htmlEntities(statusResponse.status) + '</span>')
            else
                $('#check-api-key-result').html('<span class="text-error">' + htmlEntities(statusResponse.status) + '</span>')

            clearTimeout(showKeyStatusMessageTimer);
            showKeyStatusMessageTimer = setTimeout(function () {
                $('#check-api-key-result').html('');
            }, displayMessageTime);
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;
            console.log(errorMsg);
            $("#genTokenResponse").html('<span class="text-error font-bold">Error: encountered an HTTP error, see JS console for details.</span>');
        }
    });
}

function saveAPIKeyInBrowser() {
    var key = $('#config-api-key').val().trim();
    localStorage.setItem('apiKey', key);
    document.cookie = 'isAPIKeyConfigured=true; secure; path=/';
    showSuccessAlert('Saved API key in browser.');
}

function deleteAPIKeyFromBrowser() {
    localStorage.removeItem('apiKey');
    document.cookie = 'isAPIKeyConfigured=false; secure; path=/';
    showSuccessAlert('Cleared saved API key from browser.');
}

function copyGeneratedKeyToClipboard() {
    navigator.clipboard.writeText($('#generated-api-key').html());
    showSuccessAlert('Saved generated API key to clipboard.');
}

function saveGeneratedKeyInBrowser() {
    var key = $('#generated-api-key').html();
    localStorage.setItem('apiKey', key);
    document.cookie = 'isAPIKeyConfigured=true; secure; path=/';
    showSuccessAlert('Saved generated API key in browser.');
}

function retrieveAndShowVersion () {
    $("#search-vulns-version-content").html(`<span class="loading loading-spinner text-center"></span>`);
    $.get({
        url: "/api/version",
        success: function (versionResponse) {
            $("#search-vulns-version-content").html(`<table class="table table-sm max-w-md"><tr class="text-sm"><td>search_vulns Version:</td><td>${versionResponse.version}</td></tr><tr class="text-sm"><td>Last Resource Update:</td><td>${versionResponse.last_db_update}</td></tr></table>`);
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;
            console.log(errorMsg);
            $("#search-vulns-version-content").html('<span class="text-error font-bold">Error: encountered an HTTP error, see JS console for details.</span>');
        }
    });
}

/* init */

// display version
retrieveAndShowVersion();

// check for API key
if (localStorage.getItem('apiKey') !== null)
    document.cookie = 'isAPIKeyConfigured=true; secure; path=/';
