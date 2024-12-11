function loadHTMLComponent(componentId, url) {
    const xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            document.getElementById(componentId).innerHTML = this.responseText;
        }
    };
    xhr.open("GET", url, true);
    xhr.send();
}