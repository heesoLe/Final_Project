/*상품 QNA 목록 조회*/
function GsQNA_search(){
	   var searchType =  $('#search_type').val();
	   var searchField =  $('#search_field').val();
   
	  var adminTab = $('#adminTab4').attr('value');
	  console.log(adminTab);

  $.ajax({//$는 jQuery란 뜻. $.ajax 뜻은 jQuery 내의 아작스 실행
      url:"/admin_list", //url 패턴 매핑주소 경로
      type:"POST",//데이터를 서버로 보내는 방법
      data: {
      	"search_field" : searchField,
      	"search_type" : searchType,
      	"adminTab" : adminTab
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",//서버의 실행된 결과값을 사용자로 받아오는 자료형
		traditional : true,
      success: function (res) {	
        		var qlist = res.qlist;
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
 		$('#ajaxhome').empty();
 		
        var GsQNACountHtml = "<div align='right'>총 문의글 수: " + res.GsQNA_count + "개</div>";
        $('#ajaxHead').append(GsQNACountHtml);

        var table_head = `
          <h3 align="center">&nbsp;상품 QNA&nbsp;목록 관리</h3>
          <table align="center">
            <tr>
              <td align="center">
                <select name="search_type" id="search_type">
                  <option value="All" ${searchType == 'All' ? 'selected' : ''}>전체</option>
                  <option value="qna_title" ${searchType == 'qna_title' ? 'selected' : ''}>제목</option>
                  <option value="qna_mem_id" ${searchType == 'qna_mem_id' ? 'selected' : ''}>작성자</option>
                </select> 
                <input id="search_field" name="search_field" size="20"> &nbsp;&nbsp;&nbsp;
                <input type="button" id="btn" name="search" value="검색" onclick="GsQNA_search();" />
              </td>
            </tr>
          </table>
          <p>
          <p>
          `
          $('#ajaxHead').append(table_head);
          
          $('#ajaxTh').empty();
          
          var table_th = `
					<tr>
							<th width="100;" height="50">No</th> 
							<th width="100">답변 유무</th>
							<th width="200;">상품 NO</th> 
							<th width="200;">제목</th> 
							<th width="200">작성자</th> 
							<th width="200;">작성일</th> 
						</tr> 
        `;

        $('#ajaxTh').append(table_th);

		   $('#ajaxTable').empty();	
		 for(let i = 0; i < qlist.length; i++){
		 var QNAReply = qlist[i].qna_reply;
			 const html = `
				<tr>
  			 <td>${qlist[i].qna_no}</td>
             ${QNAReply !== ' ' ? '<td>답변완료</td>' : '<td>대기</td>'}
			 <td>${qlist[i].qna_product_no}</td>
			 <td><a onclick="GsQNA_reply(${qlist[i].qna_no})" style="cursor:pointer; color:#0d6efd;">${qlist[i].qna_title}</a> </td>
			 <td>${qlist[i].qna_mem_id}</td>
			 <td>${qlist[i].qna_date.substring(0,10)}</td>
			 </tr>
			 `
             //통신 성공시 탭 내용담는 div를 읽어들인 값으로 채운다.
             $('#ajaxTable').append(html); 
             
             
  		 }
	  }
    });//$.ajax
}


//상품 QNA 게시판 답변
function GsQNA_reply(qna_no){
	
  $.ajax({
      url:"/GsQNA_reply", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"qna_no" : qna_no
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {	
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
 		$('#ajaxhome').empty();

        var table_head = `
					<div class="inquire-table-div">
				  <input type="hidden" id="qna_no" name="qna_no" value="${res.qna_no}">
				   <table align="center" class="inquire-table"> 
				    <tr> 
				    	<th rowspan="2" align="center">상품 번호</th> 
				    	<td><input type="text" id="qna_product_no" value="${res.qna_product_no }" readonly ></td>
				    </tr>
				    		
				    <th></th>
				    				    		    			     
				    <tr>
					     <th align="center" >작성자</th>
					     <td><input type="text" id="qna_mem_id" value="${res.qna_mem_id }" readonly ></td>
				    </tr>
				    
				    <tr>
					    <th>제목</th>
					    <td><input type="text" id="qna_title" value="${res.qna_title }" class="rag-title" name="reg-title" readonly ></td>
				    </tr>
				    
				    <tr>
					    <th>문의내용</th>
					    <td><textarea id="qna_cont" cols="30" rows="3" readonly >${res.qna_content}</textarea></td>
				    </tr>
				    
				    <tr>
				    <th>문의 답글</th>
				    <td>

					    <textarea id="qna_reply" cols="30" rows="3"  placeholder="내용을 수정해주세요." name="qna_reply" >${res.qna_reply}</textarea>

				    </td>
				    </tr>
     				</table>
     				<input id="btn" type="submit" value="등록" onclick="return reply_check1();"> &nbsp;
     				<input id="btn" type="button" value="취소" onclick="GsQNA_search();" >
     			</div>
				
				</div> 
				
				
          `
          $('#ajaxHead').append(table_head);
	  }
    });//$.ajax
};


//1대1 문의게시판 답글 ok
function GsQNA_reply_ok(){
	
  $.ajax({
      url:"/GsQNA_reply_ok", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"qna_no" : $('#qna_no').val()
      	, "qna_product_no" : $('#qna_product_no').val()
      	, "qna_mem_id" : $('#qna_mem_id').val()
      	, "qna_title" : $('#qna_title').val()
      	, "qna_cont" : $('#qna_cont').val()
      	, "qna_reply" : $('#qna_reply').val()
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {	
		alert('답변등록 성공');
		GsQNA_search();
		//location='admin_main'
	  }
    });//$.ajax
};


	function reply_check1() {
		var answer;
		answer=confirm("답변을 등록하시겠습니까?");
							
		if(answer == true){
			GsQNA_reply_ok();
			return true;
		} else if (answer == false){
			return false;
		}
	}