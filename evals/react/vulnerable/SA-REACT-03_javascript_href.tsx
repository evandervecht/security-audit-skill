// SA-REACT-03: Dynamic href from user input — javascript: protocol risk
function UserLink({ url }: { url: string }) {
  return <a href={url}>Visit site</a>;
}
