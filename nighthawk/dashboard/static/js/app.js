// NIGHTHAWK OSINT dashboard client helpers

document.addEventListener('htmx:afterRequest', function (evt) {
  // Highlight newly inserted result rows briefly
  var row = evt.target.closest('tr');
  if (row) {
    row.style.background = 'rgba(57, 255, 20, 0.12)';
    setTimeout(() => row.style.background = '', 900);
  }
});
