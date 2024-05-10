var default_theme = "dim";
var grecaptchaWidget, recaptchaLoaded = false;
var recaptchaSize = "";

function changeTheme(themeElement) {
    var theme, previousTheme = document.documentElement.getAttribute('data-theme');
    if (themeElement != null)
        theme = themeElement.id.split('-').slice(-1)[0];
    else {
        theme = default_theme;
        themeElement = $('#theme-option-' + default_theme);
    }
    document.documentElement.setAttribute("data-theme", theme);
    $('#theme-selector').find('li a').removeClass('active');
    $('#theme-selector').find('li a span').remove();
    $(themeElement).find('a').addClass('active');
    $(themeElement).find('a').append('<span class="text-right"><i class="fa-solid fa-check"></i></span>');
    localStorage.setItem("theme", theme);

    // change reCAPTCHA theme by replacing the HTML element with a new one if theme type changes (light/dark)
    var themeType = 'dark', previousThemeType = 'dark';
    if (['light', 'autumn', 'fantasy'].includes(theme))
        themeType = 'light';
    if (['light', 'autumn', 'fantasy'].includes(previousTheme))
        previousThemeType = 'light';

    if (recaptchaLoaded && ($('#grecaptcha').hasClass("hidden") || themeType != previousThemeType)) {
        $('#grecaptcha').addClass('hidden');

        var sitekey = $('#grecaptcha').attr('data-sitekey');
        var oldClasses = $('#grecaptcha')[0].className;
        if (grecaptchaWidget !== undefined) {
            grecaptcha.reset(grecaptchaWidget);
        }

        var newRecaptchaContainer = document.createElement('div');
        newRecaptchaContainer.className = oldClasses;
        newRecaptchaContainer.setAttribute('data-sitekey', sitekey);
        $('#grecaptcha').replaceWith(newRecaptchaContainer);
        newRecaptchaContainer.id = 'grecaptcha';

        grecaptchaWidget = grecaptcha.render(newRecaptchaContainer, {
            'sitekey': sitekey,
            'theme': themeType,
            'size': recaptchaSize
        });
        // fix some flashing in dark mode, since white background is rendered first
        setTimeout(function () {
            $('#grecaptcha').removeClass('hidden');
        }, 400);
    }
}

function onRecaptchaLoaded() {
    recaptchaLoaded = true;
    if (localStorage.getItem('theme') !== null)
        changeTheme($('#theme-option-' + localStorage.getItem('theme'))[0]);
    else
        changeTheme();
}


// set theme
document.addEventListener('DOMContentLoaded', function() {
    if (localStorage.getItem('theme') !== null)
        changeTheme($('#theme-option-' + localStorage.getItem('theme'))[0]);
    else
        changeTheme();

    document.body.classList.remove('hidden');
});
