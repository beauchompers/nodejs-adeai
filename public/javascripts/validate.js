$(document).ready(function(){
  window.setTimeout("fadeError();", 5000);
$('#login').submit(function(event){
var user=$('#username').val();
var pass=$('#password').val();

if(user=="")
{
$('#error').slideDown().html("<span>Please type Username</span>");
$('#error').fadeOut(3000);
return false;
}

if(pass=="")
{
$('#error').slideDown().html('<span id="error">Please type Password</span>');
$('#error').fadeOut(3000);
return false;
}

});
});

function fadeError() {
  $('#error').fadeOut(3000);
}
