//관리자 회원관리페이지

//회원검색
function member_search(){
	//$('#searchBtn').click(function(e) {
	   var searchType =  $('#search_type').val();
	   var searchField =  $('#search_field').val();

  $.ajax({//$는 jQuery란 뜻. $.ajax 뜻은 jQuery 내의 아작스 실행
      url:"/member_search", //url 패턴 매핑주소 경로
      type:"POST",//데이터를 서버로 보내는 방법
      data: {
      	"search_field" : searchField,
      	"search_type" : searchType
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",//서버의 실행된 결과값을 사용자로 받아오는 자료형
		traditional : true,
      success: function (res) {	
			 document.getElementById('ajaxTable').innerHTML = "";
		 for(let i = 0; i < res.length; i++){
			 const html = `
				<tr>
				<td></td>
  			 <td>${res[i].user_no}</td>
			 <td>${res[i].user_name}</td>
			 <td>${res[i].user_id}</td>
			 <td>${res[i].user_birth}</td>
			 <td>${res[i].join_date.substring(0,10)}</td>
			 <td>${res[i].user_phone}</td>
			 <td align="center">
			 <input id="btn" type="button" value="회원정보 수정" onclick="location.href='admin_member_edit?user_no=${res[i].user_no}'" >
			 &nbsp;&nbsp;
			 <input id="btn" type="button" value="블랙리스트 등록" onclick="location.href='admin_member_black?user_no=${res[i].user_no}'" /> 
			 </td>						 
			 
			 </tr>
			 `
             //통신 성공시 탭 내용담는 div를 읽어들인 값으로 채운다.
             $('#ajaxTable').append(html); 
  		 }
	  }
    });//$.ajax
    	//  });
/* end */	
//});
}

//관리자 문의게시판 관리페이지

//문의게시판 검색
function CSBoard_search(){
	//$('#searchBtn').click(function(e) {
	   var searchType =  $('#search_type').val();
	   var searchField =  $('#search_field').val();

  $.ajax({//$는 jQuery란 뜻. $.ajax 뜻은 jQuery 내의 아작스 실행
      url:"/CSBoard_search", //url 패턴 매핑주소 경로
      type:"POST",//데이터를 서버로 보내는 방법
      data: {
      	"search_field" : searchField,
      	"search_type" : searchType
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",//서버의 실행된 결과값을 사용자로 받아오는 자료형
		traditional : true,
      success: function (res) {	
		 document.getElementById('ajaxTable').innerHTML = "";
		 for(let i = 0; i < res.length; i++){
		 var clientContReply = res[i].client_cont_reply;
			 const html = `
				<tr>
  			 <td>${res[i].client_no}</td>
             ${clientContReply !== ' ' ? '<td>답변완료</td>' : '<td>대기</td>'}
			 <td>${res[i].client_category}</td>
			 <td onclick= "location.href ='admin_CSBoard_cont?client_no=${res[i].client_no}&state=cont&user_id=${res[i].user_id}';">${res[i].client_title} </td>
			 <td>${res[i].user_id}</td>
			 <td>${res[i].client_date.substring(0,10)}</td>
			 </tr>
			 `
             //통신 성공시 탭 내용담는 div를 읽어들인 값으로 채운다.
             $('#ajaxTable').append(html); 
  		 }
	  }
    });//$.ajax
    	//  });
/* end */	
//});
}


			  



//관리자 상품관리페이지

//상품검색
function product_search(){
	//$('#searchBtn').click(function(e) {
	   var searchType =  $('#search_type').val();
	   var searchField =  $('#search_field').val();

  $.ajax({//$는 jQuery란 뜻. $.ajax 뜻은 jQuery 내의 아작스 실행
      url:"/product_search", //url 패턴 매핑주소 경로
      type:"POST",//데이터를 서버로 보내는 방법
      data: {
      	"search_field" : searchField,
      	"search_type" : searchType
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",//서버의 실행된 결과값을 사용자로 받아오는 자료형
		traditional : true,
      success: function (res) {	
			 document.getElementById('ajaxTable').innerHTML = "";
		 for(let i = 0; i < res.length; i++){
			 const html = `
				<tr>
				<td></td>
  			 <td>${res[i].product_no}</td>
			 <td>${res[i].product_title}</td>
			 <td>${res[i].product_maker}</td>
			 <td>${res[i].product_type}</td>
			 <td>${res[i].product_type2}</td>
			 <td>${res[i].product_price}</td>
			 <td>${res[i].product_date.substring(0,10)}</td>
			 <td align="center">
			 <input id="btn" type="button" value="수정" > 
			 </td>						 
			 
			 </tr>
			 `
             //통신 성공시 탭 내용담는 div를 읽어들인 값으로 채운다.
             $('#ajaxTable').append(html); 
  		 }
	  }
    });//$.ajax
    	//  });
/* end */	
//});
}