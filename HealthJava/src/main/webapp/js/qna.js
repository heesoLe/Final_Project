$('.qna').click(function(e) {
  var kind = $(e.target).attr('data-tab');
  var url = window.location.href;
  var product_no = url.substring(url.lastIndexOf('/') + 1);

  $.ajax({
    type: 'POST',
    url: '/product/qna',
    data: {
      "kind": kind,
      "product_no": product_no
    },
    dataType: 'text',
    success: function(data) {
		
		
		
      if (data == 1) {
        alert('로그인을 해야합니다');
      }

      if (data == 2) {
        $('#tab3Content').empty();

        const html = `
          <form id="productInquiryForm" action="/qna/add_ok" method="POST">
            <input type="hidden" id="product_no" name="product_no" value="${product_no}"/>
            <label for="qnaTitle">질문 제목:</label>
            <input type="text" id="qnaTitle" name="qnaTitle" required>
            <br>
            <label for="qnaContent">질문 내용:</label>
            <textarea id="qnaContent" name="qnaContent" required></textarea>
            <br>
            <input type="submit" value="문의하기" >
            <input type="button" id="cancelButton" onclick="location.reload();"  value="취소">
          </form>
        `;

        $('#tab3Content').append(html);
      }
    }
  });
});