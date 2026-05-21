module.exports = async ({github, context, prUrl, revisionSuffix, prNumber}) => {
  const commentBody = `## 🚀 Deployment Preview

**PR Preview URL:** ${prUrl}
**Revision:** \`${revisionSuffix}\`

**Health Check:** ${prUrl}/healthcheck

This preview will receive no traffic by default. To test, use the URL above with the \`pr${prNumber}\` tag.`;

  const { data: comments } = await github.rest.issues.listComments({
    issue_number: context.issue.number,
    owner: context.repo.owner,
    repo: context.repo.repo,
  });

  const botComment = comments.find(comment =>
    comment.user.type === 'Bot' &&
    comment.body.includes('🚀 Deployment Preview')
  );

  if (botComment) {
    await github.rest.issues.updateComment({
      comment_id: botComment.id,
      owner: context.repo.owner,
      repo: context.repo.repo,
      body: commentBody
    });
  } else {
    await github.rest.issues.createComment({
      issue_number: context.issue.number,
      owner: context.repo.owner,
      repo: context.repo.repo,
      body: commentBody
    });
  }
};
