
//관리자 문의게시판 관리페이지

//문의게시판 검색
function CSBoard_search(){
	   var searchType =  $('#search_type').val();
	   var searchField =  $('#search_field').val();
      
	  var adminTab = $('#adminTab2').attr('value');
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
		var clist = res.clist;
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
 		$('#ajaxhome').empty();
 		
        var CSBoardCountHtml = "<div align='right'>총 문의글 수: " + res.CSBoard_count + "개</div>";
        $('#ajaxHead').append(CSBoardCountHtml);

        var table_head = `
          <h3 align="center">&nbsp;문의 게시판&nbsp;관리</h3>
          <table align="center">
            <tr>
              <td align="center">
                <select name="search_type" id="search_type">
                  <option value="All" ${searchType == 'All' ? 'selected' : ''}>전체</option>
                  <option value="client_title" ${searchType == 'client_title' ? 'selected' : ''}>제목</option>
                  <option value="client_category" ${searchType == 'client_category' ? 'selected' : ''}>문의 유형</option>
                  <option value="user_id" ${searchType == 'user_id' ? 'selected' : ''}>작성자</option>
                </select> 
                <input id="search_field" name="search_field" size="20"> &nbsp;&nbsp;&nbsp;
                <input type="button" id="btn" name="search" value="검색" onclick="CSBoard_search();" />
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
						<th width="100">No</th>
						<th width="100">답변 유무</th>
						<th width="200">문의 유형</th>
						<th width="200">제목</th>
						<th width="200">작성자</th>
						<th width="200">작성일</th>
					</tr>
        `;

        $('#ajaxTh').append(table_th);
        
		$('#ajaxTable').empty();
		 for(let i = 0; i < clist.length; i++){
		 var clientContReply = clist[i].client_cont_reply;
			 const html = `
				<tr>
  			 <td>${clist[i].client_no}</td>
             ${clientContReply !== ' ' ? '<td>답변완료</td>' : '<td>대기</td>'}
			 <td>${clist[i].client_category}</td>
			 <td><a onclick="CSBoard_reply(${clist[i].client_no})" style="cursor:pointer; color:#0d6efd;">${clist[i].client_title}</a> </td>
			 <td>${clist[i].user_id}</td>
			 <td>${clist[i].client_date.substring(0,10)}</td>
			 </tr>
			 `
             //통신 성공시 탭 내용담는 div를 읽어들인 값으로 채운다.
             $('#ajaxTable').append(html); 
  		 }
	  }
    });//$.ajax

}


//1대1 문의게시판 답글
function CSBoard_reply(client_no){
	
  $.ajax({
      url:"/CSBoard_reply", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"client_no" : client_no
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
				  <input type="hidden" id="client_no" name="client_no" value="${res.client_no}">
				   <table align="center" class="inquire-table"> 
				    <tr> 
				    	<th rowspan="2" align="center">문의 유형</th> 
				    	<td><input type="text" id="client_category" value="${res.client_category }" readonly ></td>
				    </tr>
				    		
				    <th></th>
				    				    		    			     
				    <tr>
					     <th align="center" >작성자</th>
					     <td><input type="text" id="user_id" value="${res.user_id }" readonly ></td>
				    </tr>
				    
				    <tr>
					    <th>제목</th>
					    <td><input type="text" id="client_title"  value="${res.client_title }" class="rag-title" name="reg-title" readonly ></td>
				    </tr>
				    
				    <tr>
					    <th>문의내용</th>
					    <td><textarea id="client_cont" cols="30" rows="3" readonly >${res.client_cont }</textarea></td>
				    </tr>
				    
				    <tr>
				    <th>문의 답글</th>
				    <td>
				    	
					    <textarea cols="30" rows="3" id="client_cont_reply" placeholder="내용을 수정해주세요." name="client_cont_reply" >${res.client_cont_reply}</textarea>
					    		    
				    </td>
				    </tr>
     				</table>
     				<input id="btn" type="button" value="등록" onclick="return reply_check()"> &nbsp;
     				<input id="btn" type="button" value="취소" onclick="CSBoard_search()" >
     			</div>
				
				</div> 
				
          `
          $('#ajaxHead').append(table_head);
	  }
    });//$.ajax
};


//1대1 문의게시판 답글 ok
function CSBoard_reply_ok(){
	
  $.ajax({
      url:"/CSBoard_reply_ok", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"client_no" : $('#client_no').val()
      	, "client_category" : $('#client_category').val()
      	, "user_id" : $('#user_id').val()
      	, "client_title" : $('#client_title').val()
      	, "client_cont" : $('#client_cont').val()
      	, "client_cont_reply" : $('#client_cont_reply').val()
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {	
		alert('답변등록 성공');
		CSBoard_search();
		//location='admin_main'
	  }
    });//$.ajax
};


	function reply_check() {
		var answer;
		answer=confirm("답변을 등록하시겠습니까?");
							
		if(answer == true){
			CSBoard_reply_ok();
			return true;
		} else if (answer == false){
			return false;
		}
	}