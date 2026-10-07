// SA-REACT-01: dangerouslySetInnerHTML with unsanitized user input
function Comment({ userComment }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: userComment }} />
  );
}
