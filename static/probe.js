$(function() {
  var form = $('#probeform');
  if (form.length < 0)
    return;

  form.submit(function() {
    var url = $('input[name="url"]', this).val();
    if (!url.match(/^https?/))
      url = 'http://' + url;
    var results = $('div.results')
      .html('<img src="/static/spinner.gif" class=spinner>');
    $.ajax({url: '/_probe', data:{url: url}, success: function(data) {
      results.html(data);
    }});
    return false;
  });
});
