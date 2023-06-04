/**
 * 
 */
/*myPage_updateAddress.jsp*/
$(document).ready(function () {
    $("#btnUpdate").click(function () {
        if (confirm("수정하시겠습니까?")) {
            action = "${path}/mypage/addr_edit_ok";
        }
    });
});
$(document).ready(function () {
    $("#btnDelete").click(function () {
        if (confirm("삭제하시겠습니까?")) {
            action = "${path}/mypage/addr_delete_ok";
        }
    });
});