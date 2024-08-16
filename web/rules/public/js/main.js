$(document).ready(function() {
  
  $('.metadata-values').hide();

  $('#metadataSelect').change(function() {
      $('.metadata-values').hide();
      const selectedMetadata = $(this).val();
      $('#' + selectedMetadata + 'Values').show();
  });

  $('#searchButton').click(function() {
    const selectedMetadata = $('#metadataSelect').val();
    const selectedValueDropdownId = selectedMetadata + 'Values';
    const selectedValue = $('#' + selectedValueDropdownId).val();
    
    console.log(`Filtering on [${selectedMetadata}] with value [${selectedValue}]`);

    $('.rule-card').hide();

    if (selectedMetadata && selectedValue) {
        
        if (selectedMetadata === 'author') {

            $('.rule-card').each(function() {

                const authorContent = $(this).find('.card-author').text();
                if (authorContent.includes(selectedValue)) {
                    $(this).show();
                }
            });

        } else if (selectedMetadata === "namespace") {
            $(`.rule-card[data-${selectedMetadata}^="${selectedValue}"]`).show();

        } else if (selectedMetadata === "mbc") {
          $(`.rule-card[data-${selectedMetadata}*="${selectedValue}"]`).show();
        } else if (selectedMetadata === "attck") {
            $(`.rule-card[data-attck*="${selectedValue}"]`).show();
        } else {
            $(`.rule-card[data-${selectedMetadata}="${selectedValue}"]`).show();
        }

    } else {
        $('.rule-card').show();  
    }
});
});
