const setAuthenticated = (data) => {
		
	console.log(JSON.stringify(data));
	
	$('#login').html(data?.login || 'not specified');
	$('#email').html(data?.email || 'not specified');
	$('#name').html(data?.name || 'not specified');
	$('#bio').html(data?.bio || 'not specified');
	$('#location').html(data?.location || 'not specified');
	
	let visibleItem, hiddenItem;
	
	if (data)
	{
		visibleItem = $('.authenticated')
		hiddenItem = $('.login')
	}
	
	else
	{
		visibleItem = $('.login')
		hiddenItem = $('.authenticated')
	}
	
	visibleItem.show();
	hiddenItem.hide();
	
};

const updatePageByAuthenticationStatus = () => {
	
	$.get('/user')
		.done(setAuthenticated)
		.fail(
			() => {
				
				setAuthenticated();
				
				$.get('/error')
					.done((data) => {
						
						 $('.error').html(data || '');
						 
					});
			}
		);
}

const logoutCurrentUser = () => {
	
	$.post(
		'/logout',
		() => setAuthenticated()
	)
}